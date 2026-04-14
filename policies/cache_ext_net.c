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
#include <stdbool.h>

typedef unsigned long long u64;
typedef unsigned int u32;

#include "dir_watcher.h"
#include "cache_ext_net.skel.h"
#include "cache_ext_policy_watch.h"

char *USAGE =
    "Usage: ./cache_ext_net --cgroup_path <path> (--watch_dir <dir> | --dual_pair <root>)\n";

struct cmdline_args {
    char *cgroup_path;
    char *watch_dir;
    char *dual_pair;
};

static struct argp_option options[] = {
    { "cgroup_path", 'c', "PATH", 0, "Path to cgroup" },
    { "watch_dir",   'w', "DIR",  0, "Directory to watch" },
    { "dual_pair", CACHE_EXT_ARG_DUAL_PAIR, "DIR", 0,
      "Dual DB root (contains client1/ and client2/)" },
    { 0 },
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct cmdline_args *args = state->input;
    switch (key) {
    case 'c': args->cgroup_path = arg; break;
    case 'w': args->watch_dir = arg; break;
    case CACHE_EXT_ARG_DUAL_PAIR: args->dual_pair = arg; break;
    default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static volatile sig_atomic_t exiting;
static void sig_handler(int signo) { exiting = 1; }

int main(int argc, char **argv) {
    struct cmdline_args args = { 0 };
    struct argp argp = { options, parse_opt, 0, 0 };
    char watch_dir_path[PATH_MAX];
    char path2[PATH_MAX];
    int dual = 0;
    unsigned long long root_ino1, root_ino2;

    argp_parse(&argp, argc, argv, 0, 0, &args);

    if (!args.cgroup_path) {
        fprintf(stderr, "Missing --cgroup_path\n");
        return 1;
    }
    if (cache_ext_resolve_watch_paths(args.watch_dir, args.dual_pair,
                     watch_dir_path, path2, &dual))
        return 1;

    if (cache_ext_watch_root_stat(watch_dir_path, path2, dual,
                                  &root_ino1, &root_ino2)) {
        fprintf(stderr, "watch root stat failed (need directories)\n");
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct cache_ext_net_bpf *skel = cache_ext_net_bpf__open();
    if (!skel) return 1;

    CACHE_EXT_SET_WATCH_ROOT_INOS(skel, root_ino1, root_ino2, dual);
    skel->rodata->client_tag_1 = 1;
    skel->rodata->client_tag_2 = 2;

    if (cache_ext_net_bpf__load(skel)) return 1;

    if (cache_ext_init_inode_watch_map(
            bpf_map__fd(skel->maps.inode_watchlist), watch_dir_path, path2,
            dual, true)) {
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