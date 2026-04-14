// Userspace loader for the evolved cache_ext policy.
// This is compiled against the auto-generated skeleton header.
// It does NOT change between evolutions — only the BPF program changes.

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
#include <string.h>

typedef unsigned long long u64;
typedef unsigned int u32;
typedef int s32;

#include "dir_watcher.h"
#include "cache_ext_policy_watch.h"
#include "cache_ext_evolved.skel.h"

/* Must match evaluate.py LEVELDB_PAIR_ROOT layout. */
#define DUAL_CLIENT1 "client1"
#define DUAL_CLIENT2 "client2"

struct cmdline_args {
	char *cgroup_path;
	char *watch_dir;
	char *dual_pair;
};

static struct argp_option options[] = {
	{ "cgroup_path", 'c', "PATH", 0, "Path to cgroup" },
	{ "watch_dir", 'w', "DIR", 0, "Single LevelDB directory" },
	{ "dual_pair", 1002, "DIR", 0,
	  "Dual DB: DIR/" DUAL_CLIENT1 " and DIR/" DUAL_CLIENT2 " (mutually exclusive with watch_dir)" },
	{ 0 },
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cmdline_args *args = state->input;
	switch (key) {
	case 'c':
		args->cgroup_path = arg;
		break;
	case 'w':
		args->watch_dir = arg;
		break;
	case 1002:
		args->dual_pair = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static volatile sig_atomic_t exiting;
static void sig_handler(int signo) { exiting = 1; }

static int validate_dir(const char *dir, char *full_out)
{
	if (access(dir, F_OK) == -1) {
		fprintf(stderr, "Directory does not exist: %s\n", dir);
		return 1;
	}
	if (realpath(dir, full_out) == NULL) {
		perror("realpath");
		return 1;
	}
	if (strlen(full_out) > 128) {
		fprintf(stderr, "path too long (max 128): %s\n", full_out);
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct cmdline_args args = { 0 };
	struct argp argp = { options, parse_opt, 0, 0 };
	char path1[PATH_MAX];
	char path2[PATH_MAX];
	char pair_root[PATH_MAX];
	char pair_sub1[PATH_MAX];
	char pair_sub2[PATH_MAX];

	argp_parse(&argp, argc, argv, 0, 0, &args);

	if (!args.cgroup_path) {
		fprintf(stderr, "Missing --cgroup_path\n");
		return 1;
	}
	if (args.dual_pair && args.watch_dir) {
		fprintf(stderr, "Use only one of --watch_dir or --dual_pair\n");
		return 1;
	}
	if (!args.dual_pair && !args.watch_dir) {
		fprintf(stderr, "Missing --watch_dir or --dual_pair\n");
		return 1;
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	bool dual = args.dual_pair != NULL;
	unsigned long long root_ino1, root_ino2;

	if (dual) {
		if (validate_dir(args.dual_pair, pair_root))
			return 1;
		snprintf(pair_sub1, sizeof(pair_sub1), "%s/%s", pair_root, DUAL_CLIENT1);
		snprintf(pair_sub2, sizeof(pair_sub2), "%s/%s", pair_root, DUAL_CLIENT2);
		if (validate_dir(pair_sub1, path1))
			return 1;
		if (validate_dir(pair_sub2, path2))
			return 1;
	} else {
		if (validate_dir(args.watch_dir, path1))
			return 1;
		path2[0] = '\0';
	}

	if (cache_ext_watch_root_stat(path1, path2, dual, &root_ino1, &root_ino2)) {
		fprintf(stderr, "watch root stat failed (need directories)\n");
		return 1;
	}

	struct cache_ext_evolved_bpf *skel = cache_ext_evolved_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	CACHE_EXT_SET_WATCH_ROOT_INOS(skel, root_ino1, root_ino2, dual);
	skel->rodata->client_tag_1 = 1;
	skel->rodata->client_tag_2 = 2;

	if (cache_ext_evolved_bpf__load(skel)) {
		fprintf(stderr, "Failed to load BPF program\n");
		return 1;
	}

	int map_fd = bpf_map__fd(skel->maps.inode_watchlist);
	if (dual) {
		if (initialize_dual_watch_dir_maps(path1, path2, map_fd, 1, 2)) {
			perror("Failed to initialize dual inode watch maps");
			return 1;
		}
	} else {
		if (initialize_watch_dir_map(path1, map_fd, true)) {
			perror("Failed to initialize watch_dir map");
			return 1;
		}
	}

	int cgroup_fd = open(args.cgroup_path, O_RDONLY);
	if (cgroup_fd < 0) {
		perror("Failed to open cgroup path");
		return 1;
	}

	struct bpf_link *link = bpf_map__attach_cache_ext_ops(
		skel->maps.evolved_ops, cgroup_fd);
	if (!link) {
		perror("Failed to attach struct_ops");
		return 1;
	}

	if (cache_ext_evolved_bpf__attach(skel)) {
		perror("Failed to attach kprobes");
		return 1;
	}

	if (dual)
		printf("Evolved policy loaded (dual DB): %s -> tags 1,2\n", args.dual_pair);
	else
		printf("Evolved policy loaded for directory: %s\n", path1);
	printf("Press Ctrl+C to stop.\n");
	fflush(stdout);

	signal(SIGINT, sig_handler);
	while (!exiting)
		sleep(1);

	bpf_link__destroy(link);
	cache_ext_evolved_bpf__destroy(skel);
	close(cgroup_fd);
	printf("Evolved policy unloaded.\n");
	return 0;
}
