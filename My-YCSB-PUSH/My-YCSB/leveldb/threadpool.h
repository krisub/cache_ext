#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <syscall.h>  // For getting thread IDs on Linux
#include <unistd.h>   // For getpid() on Unix
#include <condition_variable>
#include <functional>
#include <future>
#include <iostream>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

// BPF
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

inline void clear_bpf_map(int map_fd) {
    // Clearing the map
    int key;
    while (bpf_map_get_next_key(map_fd, NULL, &key) == 0) {
        if (bpf_map_delete_elem(map_fd, &key) != 0) {
            perror("Failed to delete key");
            throw std::runtime_error("Failed to delete key");
        }
    }
}

class ThreadPool {
   public:
    ThreadPool(size_t threads) : stop(false) {
        for (size_t i = 0; i < threads; ++i)
            workers.emplace_back([this] {
                // Get the thread ID
                long ret = syscall(SYS_gettid);
                if (ret < 0) {
                    throw std::runtime_error("Failed to get thread ID");
                }
                {
                    std::unique_lock<std::mutex> lock(this->queue_mutex);
                    thread_pids.push_back((int)ret);
                }

                for (;;) {
                    std::function<void()> task;

                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        this->condition.wait(lock, [this] {
                            return this->stop || !this->tasks.empty();
                        });
                        if (this->stop && this->tasks.empty()) return;
                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                    }

                    task();
                }
            });
    }

    template <class F, class... Args>
    auto enqueue(F&& f, Args&&... args)
        -> std::future<typename std::result_of<F(Args...)>::type> {
        using return_type = typename std::result_of<F(Args...)>::type;

        auto task = std::make_shared<std::packaged_task<return_type()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...));

        std::future<return_type> res = task->get_future();
        {
            std::unique_lock<std::mutex> lock(queue_mutex);

            // don't allow enqueueing after stopping the pool
            if (stop) throw std::runtime_error("enqueue on stopped ThreadPool");

            tasks.emplace([task]() { (*task)(); });
        }
        condition.notify_one();
        return res;
    }

    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for (std::thread& worker : workers) worker.join();
    }

    std::vector<pid_t> get_threadpool_pids() const { return thread_pids; }

    void fill_bpf_map_with_pids(std::string map_path) const {
        int map_fd = bpf_obj_get(map_path.c_str());
        if (map_fd < 0) {
            std::cerr << "Failed to get map file descriptor from " << map_path
                      << std::endl;
            throw std::runtime_error("Failed to get map file descriptor");
        }
        // First clear the map
        clear_bpf_map(map_fd);
        for (pid_t pid : thread_pids) {
            int key = pid;
            fprintf(stderr, "Got thread ID: (key=%d, pid=%d)\n", key, pid);
            int value = 1;
            int ret = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
            if (ret < 0) {
                throw std::runtime_error("Failed to update BPF map");
            }
        }
    }

   private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;

    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
    std::vector<pid_t> thread_pids;
};

// Main for testing
// int main() {
//     ThreadPool pool(4);
//     auto result1 = pool.enqueue([](int answer) { return answer; }, 42);
//     auto result2 = pool.enqueue([]() { std::cout << "Hello from the
//     ThreadPool" << std::endl; }); std::cout << "Result from the pool: " <<
//     result1.get() << std::endl; result2.get();  // Just to synchronize and
//     wait for output return 0;
// }

#endif
