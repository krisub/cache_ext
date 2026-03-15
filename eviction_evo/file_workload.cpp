/*
 * file_workload.c — Multithreaded file reader workload for cache_ext evolution.
 *
 * Two instances of this program run simultaneously inside a memory-limited
 * cgroup, each with a different nice value and file access pattern. The BPF
 * eviction policy must learn to prioritize pages based on scheduler features.
 *
 * What it does:
 *   - Opens files from a directory, reads them, computes CRC32 checksum
 *   - Multiple threads reading concurrently
 *   - Reports throughput (ops/sec) to stdout in a parseable format
 *
 * Usage:
 *   file_workload <config.yaml>
 *
 * YAML config:
 *   directory: /mydata/file_workload_data
 *   file_prefix: "data_"         # files named data_000000, data_000001, ...
 *   num_files: 10000
 *   num_threads: 4
 *   warmup_seconds: 10
 *   runtime_seconds: 120
 *   nice_value: -10              # set via setpriority()
 *   read_pattern: "zipfian"      # "zipfian", "uniform", or "sequential"
 *   zipfian_constant: 0.99
 *
 * Output (parseable, on stdout):
 *   overall: total throughput 12345.67 ops/sec READ average latency 456.78 ns READ p99 latency 1234.56 ns
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <stdint.h>
#include <math.h>

#include <atomic>
#include <algorithm>
#include <string>
#include <vector>
#include <random>

#include <yaml-cpp/yaml.h>

// CRC32 lookup table (IEEE polynomial)
static uint32_t crc32_table[256];

static void crc32_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c >> 1) ^ (c & 1 ? 0xEDB88320 : 0);
        crc32_table[i] = c;
    }
}

static uint32_t crc32_update(uint32_t crc, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    crc = ~crc;
    for (size_t i = 0; i < len; i++)
        crc = crc32_table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

struct config {
    std::string directory;
    std::string file_prefix;
    int num_files;
    int num_threads;
    int warmup_seconds;
    int runtime_seconds;
    int nice_value;
    std::string read_pattern;
    double zipfian_constant;
};

struct ZipfianGenerator {
    std::vector<double> cdf;
    int n;

    ZipfianGenerator() : n(0) {}

    void init(int n_, double s) {
        n = n_;
        cdf.resize(n);
        double sum = 0;
        for (int i = 0; i < n; i++)
            sum += 1.0 / pow((double)(i + 1), s);
        double running = 0;
        for (int i = 0; i < n; i++) {
            running += 1.0 / pow((double)(i + 1), s);
            cdf[i] = running / sum;
        }
    }

    int next(std::mt19937 &rng) const {
        double u = std::uniform_real_distribution<double>(0.0, 1.0)(rng);
        auto it = std::lower_bound(cdf.begin(), cdf.end(), u);
        int idx = (int)(it - cdf.begin());
        if (idx >= n) idx = n - 1;
        return idx;
    }
};

struct thread_stats {
    uint64_t ops;
    uint64_t total_latency_ns;
    uint64_t max_latency_ns;
    std::vector<uint64_t> latencies;
};

struct thread_ctx {
    int thread_id;
    const config *cfg;
    const ZipfianGenerator *zipf;
    std::atomic<bool> *warmup_done;
    std::atomic<bool> *stop;
    thread_stats stats;
};

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void *worker(void *arg) {
    thread_ctx *ctx = (thread_ctx *)arg;
    const config *cfg = ctx->cfg;

    std::mt19937 rng(ctx->thread_id * 1234 + 5678);
    std::uniform_int_distribution<int> uniform_dist(0, cfg->num_files - 1);

    char path[512];
    char read_buf[1024 * 1024]; // 1 MB read buffer
    int seq_idx = ctx->thread_id; // sequential starting point

    ctx->stats = {};
    ctx->stats.latencies.reserve(1000000);

    while (!ctx->stop->load()) {
        // Pick which file to read
        int file_idx;
        if (cfg->read_pattern == "zipfian") {
            file_idx = ctx->zipf->next(rng);
        } else if (cfg->read_pattern == "sequential") {
            file_idx = seq_idx % cfg->num_files;
            seq_idx += cfg->num_threads;
        } else {
            file_idx = uniform_dist(rng);
        }

        snprintf(path, sizeof(path), "%s/%s%06d",
                 cfg->directory.c_str(), cfg->file_prefix.c_str(), file_idx);

        uint64_t t0 = now_ns();

        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;

        uint32_t crc = 0;
        ssize_t n;
        while ((n = read(fd, read_buf, sizeof(read_buf))) > 0) {
            crc = crc32_update(crc, read_buf, (size_t)n);
        }
        close(fd);

        // Prevent compiler from optimizing away the CRC
        if (crc == 0xDEADBEEF) printf("crc=%u\n", crc);

        uint64_t elapsed = now_ns() - t0;

        if (ctx->warmup_done->load()) {
            ctx->stats.ops++;
            ctx->stats.total_latency_ns += elapsed;
            if (elapsed > ctx->stats.max_latency_ns)
                ctx->stats.max_latency_ns = elapsed;
            if (ctx->stats.latencies.size() < 10000000)
                ctx->stats.latencies.push_back(elapsed);
        }
    }

    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <config.yaml>\n", argv[0]);
        return 1;
    }

    crc32_init();

    YAML::Node root = YAML::LoadFile(argv[1]);

    config cfg;
    cfg.directory       = root["directory"].as<std::string>();
    cfg.file_prefix     = root["file_prefix"] ? root["file_prefix"].as<std::string>() : "data_";
    cfg.num_files       = root["num_files"].as<int>();
    cfg.num_threads     = root["num_threads"].as<int>();
    cfg.warmup_seconds  = root["warmup_seconds"] ? root["warmup_seconds"].as<int>() : 10;
    cfg.runtime_seconds = root["runtime_seconds"] ? root["runtime_seconds"].as<int>() : 120;
    cfg.nice_value      = root["nice_value"] ? root["nice_value"].as<int>() : 0;
    cfg.read_pattern    = root["read_pattern"] ? root["read_pattern"].as<std::string>() : "uniform";
    cfg.zipfian_constant = root["zipfian_constant"] ? root["zipfian_constant"].as<double>() : 0.99;

    // Set process nice value
    if (cfg.nice_value != 0) {
        if (setpriority(PRIO_PROCESS, 0, cfg.nice_value) != 0) {
            fprintf(stderr, "Warning: setpriority(%d) failed: %s\n",
                    cfg.nice_value, strerror(errno));
        }
    }

    fprintf(stderr, "file_workload: dir=%s files=%d threads=%d nice=%d pattern=%s "
                    "warmup=%ds runtime=%ds\n",
            cfg.directory.c_str(), cfg.num_files, cfg.num_threads,
            cfg.nice_value, cfg.read_pattern.c_str(),
            cfg.warmup_seconds, cfg.runtime_seconds);

    ZipfianGenerator zipf;
    if (cfg.read_pattern == "zipfian") {
        fprintf(stderr, "Precomputing Zipfian CDF (n=%d, s=%.4f)...\n",
                cfg.num_files, cfg.zipfian_constant);
        zipf.init(cfg.num_files, cfg.zipfian_constant);
    }

    std::atomic<bool> warmup_done{false};
    std::atomic<bool> stop{false};

    std::vector<thread_ctx> contexts((size_t)cfg.num_threads);
    std::vector<pthread_t> threads((size_t)cfg.num_threads);

    for (int i = 0; i < cfg.num_threads; i++) {
        contexts[(size_t)i].thread_id = i;
        contexts[(size_t)i].cfg = &cfg;
        contexts[(size_t)i].zipf = &zipf;
        contexts[(size_t)i].warmup_done = &warmup_done;
        contexts[(size_t)i].stop = &stop;
        pthread_create(&threads[(size_t)i], NULL, worker, &contexts[(size_t)i]);
    }

    // Warmup phase
    fprintf(stderr, "Warm-Up: running for %d seconds...\n", cfg.warmup_seconds);
    sleep((unsigned)cfg.warmup_seconds);
    warmup_done.store(true);

    // Measurement phase
    fprintf(stderr, "Measuring for %d seconds...\n", cfg.runtime_seconds);
    sleep((unsigned)cfg.runtime_seconds);
    stop.store(true);

    for (int i = 0; i < cfg.num_threads; i++) {
        pthread_join(threads[(size_t)i], NULL);
    }

    // Aggregate results
    uint64_t total_ops = 0;
    uint64_t total_latency = 0;
    std::vector<uint64_t> all_latencies;
    for (int i = 0; i < cfg.num_threads; i++) {
        total_ops += contexts[(size_t)i].stats.ops;
        total_latency += contexts[(size_t)i].stats.total_latency_ns;
        all_latencies.insert(all_latencies.end(),
                             contexts[(size_t)i].stats.latencies.begin(),
                             contexts[(size_t)i].stats.latencies.end());
    }

    double throughput = (double)total_ops / (double)cfg.runtime_seconds;
    double avg_latency = total_ops > 0 ? (double)total_latency / (double)total_ops : 0;

    // Compute p99
    double p99_latency = 0;
    if (!all_latencies.empty()) {
        std::sort(all_latencies.begin(), all_latencies.end());
        size_t p99_idx = (size_t)((double)all_latencies.size() * 0.99);
        if (p99_idx >= all_latencies.size()) p99_idx = all_latencies.size() - 1;
        p99_latency = (double)all_latencies[p99_idx];
    }

    // Output in My-YCSB-compatible format for the existing parser
    printf("overall: total throughput %.2f ops/sec "
           "READ average latency %.2f ns "
           "READ p99 latency %.2f ns\n",
           throughput, avg_latency, p99_latency);

    return 0;
}
