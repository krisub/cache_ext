#include <chrono>
#include <thread>
#include "worker.h"

void worker_thread_fn(Client *client, Workload *workload, OpMeasurement *measurement, long next_op_interval_ns) {
	Operation op = {};  // Zero-initialize to prevent stale stack values on thread stack reuse
	op.key_buffer = new char[workload->key_size];
	op.value_buffer = new char[workload->value_size];
	op.value_buffer_size = workload->value_size;
	std::chrono::steady_clock::time_point start_time, finish_time;
	std::chrono::steady_clock::time_point next_op_time = std::chrono::steady_clock::now();

	// If the workload has scans:
	// - Check the scan_worker_count field in the workload object.
	// - If it's zero, do nothing.
	// - If it's greater than zero, check the worker's id number. If it's less
	//   than the scan_worker_count, the worker should perform only scans.

	measurement->start_measure();
	while (workload->has_next_op()) {
		// Finish earlier if runtime expires
		if (measurement->finished) {
			break;
		}
		workload->next_op(&op);
		// Reset reply_value_buffer each iteration: do_get checks this for a
		// valid destination before calling memcpy, and stale/corrupt values
		// (from thread-stack reuse between warmup and benchmark phases) would
		// cause a fault when the server returns data.
		op.reply_value_buffer = nullptr;

		if (std::chrono::steady_clock::now() < next_op_time) {
			std::this_thread::sleep_until(next_op_time);
		}
		start_time = std::chrono::steady_clock::now();
		client->do_operation(&op);
		finish_time = std::chrono::steady_clock::now();
		long latency = std::chrono::duration_cast<std::chrono::nanoseconds>(finish_time - start_time).count();
		measurement->record_op(op.type, (double) latency, client->id);
		measurement->record_progress(1);
		next_op_time += std::chrono::nanoseconds(next_op_interval_ns);
	}
	measurement->finish_measure();
	client->reset();
	delete[] op.key_buffer;
	delete[] op.value_buffer;
}

void monitor_thread_fn(const char *task, OpMeasurement *measurement, long runtime_seconds) {
	double rt_throughput[NR_OP_TYPE];
	double progress;
	long epoch = 0;
	std::chrono::steady_clock::time_point start_time, curr_time;
	start_time = std::chrono::steady_clock::now();

	for (;!measurement->finished
	     ;std::this_thread::sleep_for(std::chrono::seconds(1)), ++epoch) {
		measurement->get_rt_throughput(rt_throughput);
		progress = measurement->get_progress_percent();
		printf("%s (epoch %ld, progress %.2f%%): ", task, epoch, 100 * progress);
		double total_throughput = 0;
		for (int i = 0; i < NR_OP_TYPE; ++i) {
			printf("%s throughput %.2lf ops/sec, ", operation_type_name[i], rt_throughput[i]);
			total_throughput += rt_throughput[i];
		}
		printf("total throughput %.2lf ops/sec\n", total_throughput);
		curr_time = std::chrono::steady_clock::now();
		// std::cerr << "runtime seconds: " << runtime_seconds << std::endl;
		// std::cerr << "start time: " << start_time.time_since_epoch().count() << std::endl;
		// std::cerr << "curr time: " << curr_time.time_since_epoch().count() << std::endl;
		// std::cerr << "duration seconds: " << std::chrono::duration_cast<std::chrono::seconds>(curr_time - start_time).count() << std::endl;
		if (runtime_seconds > 0 && std::chrono::duration_cast<std::chrono::seconds>(curr_time - start_time).count() >= runtime_seconds) {
			std::cout << "time's up!" << std::endl;
			measurement->finished = true;
		}
		std::cout << std::flush;
	}
	printf("%s: calculating overall performance metrics... (might take a while)\n", task);
	std::cerr << std::flush;
	measurement->final_result_lock.lock();

	/* print throughput */
	printf("%s overall: ", task);
	double total_throughput = 0;
	for (int i = 0; i < NR_OP_TYPE; ++i) {
		printf("%s throughput %.2lf ops/sec, ", operation_type_name[i], measurement->get_throughput((OperationType) i));
		total_throughput += measurement->get_throughput((OperationType) i);
	}
	printf("total throughput %.2lf ops/sec\n", total_throughput);

	/* print latency */
	printf("%s overall: ", task);
	for (int i = 0; i < NR_OP_TYPE; ++i) {
		printf("%s average latency %.2lf ns, ", operation_type_name[i], measurement->get_latency_average((OperationType) i));
		printf("%s p99 latency %.2lf ns", operation_type_name[i], measurement->get_latency_percentile((OperationType) i, 0.99f));
		if (i != NR_OP_TYPE - 1)
			printf(", ");
	}
	printf("\n");
	measurement->final_result_lock.unlock();
	std::cout << std::flush;
}

void run_workload_with_op_measurement(const char *task, ClientFactory *factory, Workload **workload_arr, int nr_thread, long nr_op, long runtime_seconds, long max_progress,
                                      long next_op_interval_ns, const char *latency_file) {
	/* allocate resources */
	Client **client_arr = new Client *[nr_thread];
	std::thread **thread_arr = new std::thread *[nr_thread];
	OpMeasurement measurement;
	for (int thread_index = 0; thread_index < nr_thread; ++thread_index) {
		client_arr[thread_index] = factory->create_client();
		measurement.enable_client(client_arr[thread_index]->id);
	}

	/* start running workload */
	measurement.set_max_progress(max_progress);
	for (int thread_index = 0; thread_index < nr_thread; ++thread_index) {
		thread_arr[thread_index] = new std::thread(worker_thread_fn, client_arr[thread_index], workload_arr[thread_index], &measurement, next_op_interval_ns);
	}
	std::thread stat_thread(monitor_thread_fn, task, &measurement, runtime_seconds);
	for (int thread_index = 0; thread_index < nr_thread; ++thread_index) {
		thread_arr[thread_index]->join();
	}
	measurement.finalize_measure();
	if (latency_file != nullptr)
		measurement.save_latency(latency_file);
	stat_thread.join();

	/* cleanup */
	for (int thread_index = 0; thread_index < nr_thread; ++thread_index) {
		factory->destroy_client(client_arr[thread_index]);
		delete thread_arr[thread_index];
	}
	delete[] client_arr;
	delete[] thread_arr;
}

void run_init_workload_with_op_measurement(const char *task, ClientFactory *factory, long nr_entry, long key_size, long value_size, int nr_thread) {
	InitWorkload **workload_arr = new InitWorkload *[nr_thread];
	long nr_entry_per_thread = (nr_entry + nr_thread - 1) / nr_thread;
	for (unsigned int thread_index = 0; thread_index < nr_thread; ++thread_index) {
		long start_key = nr_entry_per_thread * thread_index;
		long end_key = std::min(nr_entry_per_thread * (thread_index + 1), nr_entry);
		workload_arr[thread_index] = new InitWorkload(end_key - start_key, start_key, key_size, value_size, thread_index);
	}

	run_workload_with_op_measurement(task, factory, (Workload **)workload_arr, nr_thread, nr_entry, 0, nr_entry, 0, nullptr);

	for (int thread_index = 0; thread_index < nr_thread; ++thread_index) {
		delete workload_arr[thread_index];
	}
	delete[] workload_arr;
}

void run_init_trace_workload_with_op_measurement(const char *task, ClientFactory *factory, long key_size, long value_size, std::string trace_file, std::string trace_type) {
	InitTraceWorkload *workload = new InitTraceWorkload(key_size, value_size, trace_file, trace_type);
	int64_t nr_op = workload->nr_op;
	int nr_thread = 1;
	fprintf(stderr, "nr_op: %ld\n", nr_op);
	run_workload_with_op_measurement(task, factory, (Workload **)&workload, nr_thread, nr_op, 0, nr_thread * nr_op, 0, nullptr);
	delete workload;
}

void run_uniform_workload_with_op_measurement(const char *task, ClientFactory *factory, long nr_entry, long key_size, long value_size,
                                              long scan_length, int nr_thread, struct OpProportion op_prop, long nr_op, long runtime_seconds, long next_op_interval_ns,
                                              const char *latency_file) {
	UniformWorkload **workload_arr = new UniformWorkload *[nr_thread];
	for (unsigned int thread_index = 0; thread_index < nr_thread; ++thread_index) {
		workload_arr[thread_index] = new UniformWorkload(key_size, value_size, scan_length, nr_entry, nr_op, op_prop, thread_index);
	}

	run_workload_with_op_measurement(task, factory, (Workload **)workload_arr, nr_thread, nr_op, runtime_seconds, nr_thread * nr_op, next_op_interval_ns, latency_file);

	for (int thread_index = 0; thread_index < nr_thread; ++thread_index) {
		delete workload_arr[thread_index];
	}
	delete[] workload_arr;
}

void run_zipfian_workload_with_op_measurement(const char *task, ClientFactory *factory, long nr_entry, long key_size, long value_size,
                                              long scan_length, int nr_thread, struct OpProportion op_prop, double zipfian_constant, long nr_op,
											  long runtime_seconds, long next_op_interval_ns, const char *latency_file) {
	//int scan_worker_count = 1;
	ZipfianWorkload **workload_arr = new ZipfianWorkload *[nr_thread];
	printf("ZipfianWorkload: start initializing zipfian variables, might take a while\n");
	ZipfianWorkload base_workload(key_size, value_size, scan_length, nr_entry, nr_op, op_prop, zipfian_constant, 0);
	base_workload.record_keys = true;
	for (unsigned int thread_index = 0; thread_index < nr_thread; ++thread_index) {
		workload_arr[thread_index] = base_workload.clone(thread_index);
		// if (scan_worker_count > 0 && thread_index < scan_worker_count && op_prop.op[SCAN] > 0) {
		// 	workload_arr[thread_index]->do_only_scans = true;
		// } else {
		// 	workload_arr[thread_index]->do_only_scans = false;
		// }
	}

	run_workload_with_op_measurement(task, factory, (Workload **)workload_arr, nr_thread, nr_op, runtime_seconds, nr_thread * nr_op, next_op_interval_ns, latency_file);

	// // If record_keys is set, dump all keys into a file.
	// // Format as a json array of numbers.
	// if (base_workload.record_keys) {
	// 	std::ofstream key_file("workload_keys.json");
	// 	key_file << "[";
    //             for (int i = 0; i < nr_thread; i++) {
	// 				auto &workload = workload_arr[i];
    //                 for (auto it = workload->recorded_keys.begin();
    //                      it != workload->recorded_keys.end(); ++it) {
    //                     key_file << *it;
    //                     if (std::next(it) != workload->recorded_keys.end()) {
    //                         key_file << ",";
    //                     }
    //                 }
    //             }
    //             key_file << "]";
	// 	key_file.close();
	// }

	for (int thread_index = 0; thread_index < nr_thread; ++thread_index) {
		delete workload_arr[thread_index];
	}
	delete[] workload_arr;
}

void run_latest_workload_with_op_measurement(const char *task, ClientFactory *factory, long nr_entry, long key_size, long value_size,
                                             int nr_thread, double read_ratio, double zipfian_constant, long nr_op, long runtime_seconds,
											 long next_op_interval_ns, const char *latency_file) {
	LatestWorkload **workload_arr = new LatestWorkload *[nr_thread];
	printf("LatestWorkload: start initializing zipfian variables, might take a while\n");
	LatestWorkload base_workload(key_size, value_size, nr_entry, nr_op, read_ratio, zipfian_constant, 0);
	for (unsigned int thread_index = 0; thread_index < nr_thread; ++thread_index) {
		workload_arr[thread_index] = base_workload.clone(thread_index);
	}

	run_workload_with_op_measurement(task, factory, (Workload **)workload_arr, nr_thread, nr_op, runtime_seconds, nr_thread * nr_op, next_op_interval_ns, latency_file);

	for (int thread_index = 0; thread_index < nr_thread; ++thread_index) {
		delete workload_arr[thread_index];
	}
	delete[] workload_arr;
}

TraceIterator *global_trace_iter = nullptr;

void run_trace_workload_with_op_measurement(const char *task, ClientFactory *factory, long key_size, long value_size,
                                            int nr_thread, std::string trace_file, std::string trace_type, long runtime_seconds,
											long next_op_interval_ns, const char *latency_file) {
	TraceWorkload **workload_arr = new TraceWorkload *[nr_thread];
	// Create a new TraceWorkload object shared by all threads. Use new operator
	// to allocate memory for the object.
	TraceIterator *trace_iter = nullptr;
	if (global_trace_iter == nullptr) {
		trace_iter = new TraceIterator(trace_file, trace_type);
		global_trace_iter = trace_iter;
	} else {
		trace_iter = global_trace_iter;
	}
	int64_t nr_op = trace_iter->nr_op();
	fprintf(stderr, "TraceWorkload: start loading trace files, might take a while\n");
	for (unsigned int thread_index = 0; thread_index < nr_thread; ++thread_index) {
		workload_arr[thread_index] = new TraceWorkload(key_size, value_size, trace_file, thread_index);
		workload_arr[thread_index]->trace_iterator = trace_iter;
	}

	run_workload_with_op_measurement(task, factory, (Workload **)workload_arr, nr_thread, nr_op, runtime_seconds, nr_thread * nr_op, next_op_interval_ns, latency_file);

	for (int thread_index = 0; thread_index < nr_thread; ++thread_index) {
		delete workload_arr[thread_index];
	}
	delete[] workload_arr;
}
