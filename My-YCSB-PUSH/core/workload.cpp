#include <vector>
#include <random>
#include <algorithm>
#include "workload.h"
// for sys_gettid
#include <unistd.h>
#include <sys/syscall.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <iostream>

const char* operation_type_name[] = {
	"UPDATE", "INSERT", "READ", "SCAN", "READ_MODIFY_WRITE"
};

Workload::Workload(long key_size, long value_size)
: key_size(key_size), value_size(value_size) {
	;
}

long Workload::generate_random_long(unsigned int *seedp) {
	return (((long)rand_r(seedp)) << (sizeof(int) * 8)) | rand_r(seedp);
}

double Workload::generate_random_double(unsigned int *seedp) {
	return ((double)rand_r(seedp)) / RAND_MAX;
}

UniformWorkload::UniformWorkload(long key_size, long value_size, long scan_length, long nr_entry,
                                 long nr_op, struct OpProportion op_prop, unsigned int seed)
: Workload(key_size, value_size), scan_length(scan_length), nr_entry(nr_entry), nr_op(nr_op), op_prop(op_prop), seed(seed), cur_nr_op(0) {
	sprintf(this->key_format, "%%0%ldld", key_size - 1);
}

bool UniformWorkload::has_next_op() {
	return this->cur_nr_op < this->nr_op;
}

void UniformWorkload::next_op(Operation *op) {
	if (!this->has_next_op())
		throw std::invalid_argument("does not have next op");
	double op_random = this->generate_random_double(&this->seed);
	int op_random_int = 1 + (int) (op_random * 100);
	int running_sum = 0;
	if (running_sum += int(this->op_prop.op[UPDATE] * 100), op_random_int <= running_sum) {
		op->type = UPDATE;
		this->generate_value_string(op->value_buffer);
	} else if (running_sum += int(this->op_prop.op[INSERT] * 100), op_random_int <= running_sum) {
		op->type = INSERT;
		this->generate_value_string(op->value_buffer);
	} else if (running_sum += int(this->op_prop.op[READ] * 100), op_random_int <= running_sum) {
		op->type = READ;
	} else if (running_sum += int(this->op_prop.op[SCAN] * 100), op_random_int <= running_sum) {
		op->type = SCAN;
		op->scan_length = this->scan_length;
	} else if (running_sum += int(this->op_prop.op[READ_MODIFY_WRITE] * 100), op_random_int <= running_sum) {
		op->type = READ_MODIFY_WRITE;
		this->generate_value_string(op->value_buffer);
	} else {
		printf("op_random_int = %d, running_sum = %d, op_random_int == running_sum: %d\n", op_random_int, running_sum, op_random_int == running_sum);
		printf("op_prop = %f, %f, %f, %f, %f\n", this->op_prop.op[UPDATE], this->op_prop.op[INSERT], this->op_prop.op[READ], this->op_prop.op[SCAN], this->op_prop.op[READ_MODIFY_WRITE]);
		throw std::invalid_argument("failed to generate an operation");
	}
	long key = this->generate_random_long(&this->seed) % this->nr_entry;
	this->generate_key_string(op->key_buffer, key);
	++this->cur_nr_op;
	op->is_last_op = !this->has_next_op();
}

void UniformWorkload::generate_key_string(char *key_buffer, long key) {
	sprintf(key_buffer, this->key_format, key);
}

void UniformWorkload::generate_value_string(char *value_buffer) {
	for (int i = 0; i < this->value_size - 1; ++i) {
		value_buffer[i] = 'a' + (rand_r(&this->seed) % ('z' - 'a' + 1));
	}
	value_buffer[this->value_size - 1] = '\0';
}

ZipfianWorkload::ZipfianWorkload(long key_size, long value_size, long scan_length, long nr_entry, long nr_op,
                                 struct OpProportion op_prop, double zipfian_constant, unsigned int seed)
: Workload(key_size, value_size), scan_length(scan_length), nr_entry(nr_entry), nr_op(nr_op), op_prop(op_prop),
  zipfian_constant(zipfian_constant), seed(seed), cur_nr_op(0) {
	sprintf(this->key_format, "%%0%ldlu", key_size - 1);

	/* zipfian-related initialization */
	this->zetan = 0;
	for (long i = 1; i < this->nr_entry + 1; ++i) {
		this->zetan += 1.0 / (pow((double) i, this->zipfian_constant));
	}
	this->theta = this->zipfian_constant;
	this->zeta2theta = 0;
	for (long i = 1; i < 3; ++i) {
		this->zeta2theta += 1.0 / (pow((double) i, this->zipfian_constant));
	}
	this->alpha = 1.0 / (1.0 - this->theta);
	this->eta = (1 - pow(2.0 / (double) this->nr_entry, 1 - this->theta))
	            / (1 - (this->zeta2theta / this->zetan));
	this->generate_zipfian_random_ulong(true);
}

bool ZipfianWorkload::has_next_op() {
	return this->cur_nr_op < this->nr_op;
}

// void fill_bpf_map_with_scan_pid(int pid) {
// 	std::string map_path = "/sys/fs/bpf/cache_ext/scan_pids";
// 	int map_fd = bpf_obj_get(map_path.c_str());
// 	if (map_fd < 0) {
// 		std::cerr << "Failed to get map file descriptor from " << map_path
// 					<< std::endl;
// 		throw std::runtime_error("Failed to get map file descriptor");
// 	}
// 	// First clear the map
// 	int key = pid;
// 	fprintf(stderr, "Got thread ID: (key=%d, pid=%d)\n", key, pid);
// 	int value = 1;
// 	int ret = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
// 	if (ret < 0) {
// 		throw std::runtime_error("Failed to update BPF map");
// 	}
// }


void ZipfianWorkload::next_op(Operation *op) {
	if (!this->has_next_op())
		throw std::invalid_argument("does not have next op");
	double op_random = this->generate_random_double(&this->seed);
	int op_random_int = 1 + (int) (op_random * 100);
	int running_sum = 0;
	// if (!this->do_only_scans && this->op_prop.op[SCAN] > 0) {
	// 	this->op_prop.op[READ] += this->op_prop.op[SCAN];
	// 	this->op_prop.op[SCAN] = 0;
	// } else if (this->do_only_scans && this->op_prop.op[SCAN] < 1) {
	// 	this->op_prop.op[SCAN] = 1;
	// 	this->op_prop.op[READ] = 0;
	// 	this->op_prop.op[INSERT] = 0;
	// 	this->op_prop.op[UPDATE] = 0;
	// 	this->op_prop.op[READ_MODIFY_WRITE] = 0;
	// 	// fill the scan_pids map with the tid of the thread
	// 	long tid = syscall(SYS_gettid);
	// 	if (tid < 0) {
	// 		throw std::runtime_error("Failed to get thread ID");
	// 	}
	// 	// Check the env var ENABLE_BPF_SCAN_MAP
	// 	char *enable_bpf_scan_map_env = getenv("ENABLE_BPF_SCAN_MAP");
	// 	if (enable_bpf_scan_map_env != nullptr) {
	// 		fprintf(stderr, "Got ENABLE_BPF_SCAN_MAP=%s\n", enable_bpf_scan_map_env);
	// 		fill_bpf_map_with_scan_pid((int)tid);
	// 	}
	// }
	if (running_sum += int(this->op_prop.op[UPDATE] * 100), /*this->op_prop.op[UPDATE] != 0 && */ op_random_int <= running_sum) {
		op->type = UPDATE;
		this->generate_value_string(op->value_buffer);
	} else if (running_sum += int(this->op_prop.op[INSERT] * 100), /*this->op_prop.op[INSERT] != 0 &&*/ op_random_int <= running_sum) {
		op->type = INSERT;
		this->generate_value_string(op->value_buffer);
	} else if (running_sum += int(this->op_prop.op[READ] * 100), /*this->op_prop.op[READ] != 0 &&*/ op_random_int <= running_sum) {
		op->type = READ;
	} else if (running_sum += int(this->op_prop.op[SCAN] * 100), /*this->op_prop.op[SCAN] != 0 &&*/ op_random_int <= running_sum) {
		op->type = SCAN;
		op->scan_length = this->scan_length;
	} else if (running_sum += int(this->op_prop.op[READ_MODIFY_WRITE] * 100), /*this->op_prop.op[READ_MODIFY_WRITE] != 0 &&*/ op_random_int <= running_sum) {
		op->type = READ_MODIFY_WRITE;
		this->generate_value_string(op->value_buffer);
	} else {
		printf("op_random_int = %d, running_sum = %d, op_random_int == running_sum: %d\n", op_random_int, running_sum, op_random_int == running_sum);
		printf("op_prop = %f, %f, %f, %f, %f\n", this->op_prop.op[UPDATE], this->op_prop.op[INSERT], this->op_prop.op[READ], this->op_prop.op[SCAN], this->op_prop.op[READ_MODIFY_WRITE]);
		throw std::invalid_argument("failed to generate an operation");
	}
	unsigned long key = this->generate_zipfian_random_ulong(true) % ((unsigned long) this->nr_entry);
	// If record_keys is set to true, record op's key
	if (this->record_keys) {
		this->recorded_keys.push_back(key);
	}
	this->generate_key_string(op->key_buffer, key);
	++this->cur_nr_op;
	op->is_last_op = !this->has_next_op();
}

ZipfianWorkload * ZipfianWorkload::clone(unsigned int new_seed) {
	/* create a new ZipfianWorkload with a cheap nr_entry */
	ZipfianWorkload *copy = new ZipfianWorkload(this->key_size, this->value_size, this->scan_length, 3, this->nr_op,
	                                            this->op_prop, this->zipfian_constant, new_seed);
	copy->zetan = this->zetan;
	copy->theta = this->theta;
	copy->zeta2theta = this->zeta2theta;
	copy->alpha = this->alpha;
	copy->eta = this->eta;
	copy->nr_entry = this->nr_entry;
	copy->record_keys = this->record_keys;
	return copy;
}

unsigned long ZipfianWorkload::fnv1_64_hash(unsigned long value) {
	uint64_t hash = 14695981039346656037ul;
	uint8_t *p = (uint8_t *) &value;
	for (int i = 0; i < sizeof(unsigned long); ++i, ++p) {
		hash *= 1099511628211ul;
		hash ^= *p;
	}
	return (unsigned long) hash;
}

unsigned long ZipfianWorkload::generate_zipfian_random_ulong(bool hash) {
	double u = this->generate_random_double(&this->seed);
	double uz = u * this->zetan;
	if (uz < 1)
		return 0;
	if (uz < 1 + pow(0.5, this->theta))
		return 1;
	unsigned long ret = (unsigned long) ((double)this->nr_entry * pow(this->eta * u - this->eta + 1, this->alpha));
	if (hash)
		return ZipfianWorkload::fnv1_64_hash(ret);
	else
		return ret;
}

void ZipfianWorkload::generate_key_string(char *key_buffer, unsigned long key) {
	sprintf(key_buffer, this->key_format, key);
}

void ZipfianWorkload::generate_value_string(char *value_buffer) {
	for (int i = 0; i < this->value_size - 1; ++i) {
		value_buffer[i] = 'a' + (rand_r(&this->seed) % ('z' - 'a' + 1));
	}
	value_buffer[this->value_size - 1] = '\0';
}

InitWorkload::InitWorkload(long nr_entry, long start_key, long key_size, long value_size, unsigned int seed)
: Workload(key_size, value_size), nr_entry(nr_entry), start_key(start_key), cur_nr_entry(0), seed(seed) {
	sprintf(this->key_format, "%%0%ldld", key_size - 1);
	// Generate a random shuffle of all keys from 0 to nr_entry - 1
	printf("Generating a random shuffle of all keys from 0 to %ld - 1\n", nr_entry);
	for (unsigned long i = 0; i < nr_entry; ++i)
		this->key_shuffle.push_back(i);
	std::shuffle(this->key_shuffle.begin(), this->key_shuffle.end(), std::default_random_engine(seed));
	printf("Done generating a random shuffle of all keys from 0 to %ld - 1\n", nr_entry);
}

bool InitWorkload::has_next_op() {
	this->lock.lock();
	auto ret = this->cur_nr_entry < this->nr_entry;
	this->lock.unlock();
	return ret;
}

bool InitWorkload::has_next_op_unsafe() {
	return this->cur_nr_entry < this->nr_entry;
}

void InitWorkload::next_op(Operation *op) {
	this->lock.lock();
	if (!this->has_next_op_unsafe())
		throw std::invalid_argument("does not have next op");
	op->type = INSERT;
	this->generate_key_string(op->key_buffer, this->start_key + (long)this->key_shuffle[this->cur_nr_entry++]);
	this->generate_value_string(op->value_buffer);
	op->is_last_op = !this->has_next_op_unsafe();
	this->lock.unlock();
}

void InitWorkload::generate_key_string(char *key_buffer, long key) {
	sprintf(key_buffer, this->key_format, key);
}

void InitWorkload::generate_value_string(char *value_buffer) {
	for (int i = 0; i < this->value_size - 1; ++i) {
		value_buffer[i] = 'a' + (rand_r(&this->seed) % ('z' - 'a' + 1));
	}
	value_buffer[this->value_size - 1] = '\0';
}

LatestWorkload::LatestWorkload(long key_size, long value_size, long nr_entry, long nr_op, double read_ratio,
                               double zipfian_constant, unsigned int seed)
	: Workload(key_size, value_size), nr_entry(nr_entry), nr_op(nr_op), read_ratio(read_ratio),
	  zipfian_constant(zipfian_constant), seed(seed), cur_nr_op(0), cur_ack_key(0) {
	sprintf(this->key_format, "%%0%ldlu", key_size - 1);

	/* zipfian-related initialization */
	this->zetan = 0;
	for (long i = 1; i < this->nr_entry + 1; ++i) {
		this->zetan += 1.0 / (pow((double) i, this->zipfian_constant));
	}
	this->theta = this->zipfian_constant;
	this->zeta2theta = 0;
	for (long i = 1; i < 3; ++i) {
		this->zeta2theta += 1.0 / (pow((double) i, this->zipfian_constant));
	}
	this->alpha = 1.0 / (1.0 - this->theta);
	this->eta = (1 - pow(2.0 / (double) this->nr_entry, 1 - this->theta))
		    / (1 - (this->zeta2theta / this->zetan));
	this->generate_zipfian_random_ulong(true);
}

bool LatestWorkload::has_next_op() {
	return this->cur_nr_op < this->nr_op;
}

void LatestWorkload::next_op(Operation *op) {
	if (!this->has_next_op())
		throw std::invalid_argument("does not have next op");
	bool read = this->generate_random_double(&this->seed) <= this->read_ratio;
	if (this->cur_ack_key == 0) {
		read = false;
	}
	unsigned long key;
	if (read) {
		op->type = READ;
		key = this->generate_zipfian_random_ulong(false) % (this->cur_ack_key);
		key = this->cur_ack_key - key - 1;
	} else {
		if (this->cur_ack_key >= this->nr_entry) {
			op->type = UPDATE;
			key = this->generate_zipfian_random_ulong(false) % (this->cur_ack_key);
			key = this->cur_ack_key - key - 1;
		} else {
			op->type = INSERT;
			key = this->cur_ack_key++;
		}
	}
	key = LatestWorkload::fnv1_64_hash(key) % ((unsigned long) this->nr_entry);
	this->generate_key_string(op->key_buffer, key);
	if (!read)
		this->generate_value_string(op->value_buffer);
	++this->cur_nr_op;
	op->is_last_op = !this->has_next_op();
}

LatestWorkload * LatestWorkload::clone(unsigned int new_seed) {
	/* create a new ZipfianWorkload with a cheap nr_entry */
	LatestWorkload *copy = new LatestWorkload(this->key_size, this->value_size, 3, this->nr_op,
						  this->read_ratio, this->zipfian_constant, new_seed);
	copy->zetan = this->zetan;
	copy->theta = this->theta;
	copy->zeta2theta = this->zeta2theta;
	copy->alpha = this->alpha;
	copy->eta = this->eta;
	copy->nr_entry = this->nr_entry;
	return copy;
}

unsigned long LatestWorkload::fnv1_64_hash(unsigned long value) {
	uint64_t hash = 14695981039346656037ul;
	uint8_t *p = (uint8_t *) &value;
	for (int i = 0; i < sizeof(unsigned long); ++i, ++p) {
		hash *= 1099511628211ul;
		hash ^= *p;
	}
	return (unsigned long) hash;
}

unsigned long LatestWorkload::generate_zipfian_random_ulong(bool hash) {
	double u = this->generate_random_double(&this->seed);
	double uz = u * this->zetan;
	if (uz < 1)
		return 0;
	if (uz < 1 + pow(0.5, this->theta))
		return 1;
	unsigned long ret = (unsigned long) ((double)this->nr_entry * pow(this->eta * u - this->eta + 1, this->alpha));
	if (hash)
		return LatestWorkload::fnv1_64_hash(ret);
	else
		return ret;
}

void LatestWorkload::generate_key_string(char *key_buffer, unsigned long key) {
	sprintf(key_buffer, this->key_format, key);
}

void LatestWorkload::generate_value_string(char *value_buffer) {
	for (int i = 0; i < this->value_size - 1; ++i) {
		value_buffer[i] = 'a' + (rand_r(&this->seed) % ('z' - 'a' + 1));
	}
	value_buffer[this->value_size - 1] = '\0';
}

TraceWorkload::TraceWorkload(long key_size, long value_size, std::string trace_path, unsigned int seed)
: Workload(key_size, value_size), trace_path(trace_path), seed(seed) {
	// no-op
}

bool TraceWorkload::has_next_op() {
	// TODO: Fix this
	return this->trace_iterator->has_next_op();
}

void TraceWorkload::next_op(Operation *op) {
	if (!this->has_next_op())
		throw std::invalid_argument("does not have next op");

	// Just call the iterator, wrapped in the shared_ptr
	bool has_next_op = this->trace_iterator->next_op(op);
	if (!has_next_op) {
		throw std::invalid_argument("does not have next op (2)");
	}
	if (op->type == INSERT || op->type == UPDATE) {
		this->generate_value_string(op->value_buffer);
	}
	op->is_last_op = !this->has_next_op();
}

void TraceWorkload::generate_value_string(char *value_buffer) {
	for (int i = 0; i < this->value_size - 1; ++i) {
		value_buffer[i] = 'a' + (rand_r(&this->seed) % ('z' - 'a' + 1));
	}
	value_buffer[this->value_size - 1] = '\0';
}

InitTraceWorkload::InitTraceWorkload(long key_size, long value_size, std::string trace_path, std::string trace_type)
	: TraceWorkload(key_size, value_size, trace_path, 1) {
	fprintf(stderr, "InitTraceWorkload: trace_path=%s, trace_type=%s\n", trace_path.c_str(), trace_type.c_str());
	this->trace_iterator = new TraceIterator(trace_path, trace_type);
	this->nr_op = this->trace_iterator->nr_op();
}

bool InitTraceWorkload::has_next_op() {
	return TraceWorkload::has_next_op();
}

void InitTraceWorkload::next_op(Operation *op) {
	TraceWorkload::next_op(op);
}
