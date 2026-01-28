#include <argp.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <limits.h>
#include "dir_watcher.h" 

typedef unsigned long long u64;
typedef unsigned int u32;

#include "cache_ext_net.skel.h"

char *USAGE = "Usage: ./cache_ext_net --cgroup_path <path> --watch_dir <dir>\n";

struct cmdline_args {
    char *cgroup_path;
    char *watch_dir;
};

static struct argp_option options[] = {
    { "cgroup_path", 'c', "PATH", 0, "Path to cgroup" },
    { "watch_dir",   'w', "DIR",  0, "Directory to watch" },
    { 0 },
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct cmdline_args *args = state->input;
    switch (key) {
    case 'c': args->cgroup_path = arg; break;
    case 'w': args->watch_dir = arg; break;
    default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static volatile sig_atomic_t exiting;
static void sig_handler(int signo) { exiting = 1; }

static int validate_watch_dir(const char *watch_dir, char *watch_dir_full_path) {
    if (access(watch_dir, F_OK) == -1) {
        fprintf(stderr, "Directory does not exist: %s\n", watch_dir);
        return 1;
    }
    if (realpath(watch_dir, watch_dir_full_path) == NULL) {
        perror("realpath");
        return 1;
    }
    if (strlen(watch_dir_full_path) > 128) {
        fprintf(stderr, "watch_dir path too long\n");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    struct cmdline_args args = { 0 };
    struct argp argp = { options, parse_opt, 0, 0 };
    char watch_dir_path[PATH_MAX];
    
    argp_parse(&argp, argc, argv, 0, 0, &args);

    if (!args.cgroup_path) {
        fprintf(stderr, "Missing --cgroup_path\n");
        return 1;
    }
    if (!args.watch_dir) {
        fprintf(stderr, "Missing --watch_dir\n");
        return 1;
    }
    if (validate_watch_dir(args.watch_dir, watch_dir_path)) {
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct cache_ext_net_bpf *skel = cache_ext_net_bpf__open();
    if (!skel) return 1;

    skel->rodata->watch_dir_path_len = strlen(watch_dir_path);
    strcpy(skel->rodata->watch_dir_path, watch_dir_path);

    if (cache_ext_net_bpf__load(skel)) return 1;

    if (initialize_watch_dir_map(watch_dir_path, bpf_map__fd(skel->maps.inode_watchlist), true)) {
        perror("Failed to initialize watch_dir map");
        return 1;
    }

    // 3. Attach Struct Ops
    int cgroup_fd = open(args.cgroup_path, O_RDONLY);
    if (cgroup_fd < 0) {
        perror("Failed to open cgroup path");
        return 1;
    }
    
    struct bpf_link *link = bpf_map__attach_cache_ext_ops(skel->maps.net_ops, cgroup_fd);
    if (!link) {
        perror("Failed to attach ops");
        return 1;
    }

    // 4. Attach Standard Hooks
    if (cache_ext_net_bpf__attach(skel)) {
        perror("Failed to attach tracepoints");
        return 1;
    }

    printf("Policy loaded for directory: %s\n", watch_dir_path);
    printf("Press Ctrl+C to stop.\n");

    signal(SIGINT, sig_handler);
    while (!exiting) sleep(1);

    bpf_link__destroy(link);
    cache_ext_net_bpf__destroy(skel);
    close(cgroup_fd);
    return 0;
}