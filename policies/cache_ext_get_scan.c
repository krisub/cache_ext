#include <argp.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdbool.h>

#include "cache_ext_get_scan.skel.h"
#include "dir_watcher.h"
#include "cache_ext_policy_watch.h"

char *USAGE =
	"Usage: ./cache_ext_get_scan --watch_dir <dir> | --dual_pair <root> --cgroup_path <path>\n";
struct cmdline_args {
	char *watch_dir;
	char *dual_pair;
	char *cgroup_path;
};

static struct argp_option options[] = { { "watch_dir", 'w', "DIR", 0, "Directory to watch" },
					{ "dual_pair", CACHE_EXT_ARG_DUAL_PAIR, "DIR", 0,
					  "Dual DB root (contains client1/ and client2/)" },
					{ "cgroup_path", 'c', "PATH", 0,
					  "Path to cgroup (e.g., /sys/fs/cgroup/cache_ext_test)" },
					{ 0 } };

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cmdline_args *args = state->input;
	switch (key) {
	case 'w':
		args->watch_dir = arg;
		break;
	case CACHE_EXT_ARG_DUAL_PAIR:
		args->dual_pair = arg;
		break;
	case 'c':
		args->cgroup_path = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int ret = 1;
	struct cache_ext_get_scan_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	int cgroup_fd = -1;
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	// Parse command line arguments
	struct cmdline_args args = { 0 };
	struct argp argp = { options, parse_opt, 0, 0 };
	argp_parse(&argp, argc, argv, 0, 0, &args);

	if (args.cgroup_path == NULL) {
		fprintf(stderr, "Missing required argument: cgroup_path\n");
		return 1;
	}

	char watch_dir_full_path[PATH_MAX];
	char path2[PATH_MAX];
	int dual = 0;
	unsigned long long root_ino1, root_ino2;

	if (cache_ext_resolve_watch_paths(args.watch_dir, args.dual_pair,
					 watch_dir_full_path, path2, &dual))
		return 1;

	if (cache_ext_watch_root_stat(watch_dir_full_path, path2, dual,
				      &root_ino1, &root_ino2)) {
		fprintf(stderr, "watch root stat failed (need directories)\n");
		return 1;
	}

	cgroup_fd = open(args.cgroup_path, O_RDONLY);
	if (cgroup_fd < 0) {
		perror("Failed to open cgroup path");
		return 1;
	}

	// Open skel
	skel = cache_ext_get_scan_bpf__open();
	if (skel == NULL) {
		perror("Failed to open BPF skeleton");
		goto cleanup;
	}

	CACHE_EXT_SET_WATCH_ROOT_INOS(skel, root_ino1, root_ino2, dual);
	skel->rodata->client_tag_1 = 1;
	skel->rodata->client_tag_2 = 2;

	ret = cache_ext_get_scan_bpf__load(skel);
	if (ret) {
		perror("Failed to load BPF skeleton");
		goto cleanup;
	}

	ret = cache_ext_init_inode_watch_map(
	    bpf_map__fd(skel->maps.inode_watchlist), watch_dir_full_path, path2,
	    dual, false);
	if (ret) {
		perror("Failed to initialize inode watchlist map");
		goto cleanup;
	}

	ret = bpf_map__pin(skel->maps.scan_pids, "/sys/fs/bpf/cache_ext/scan_pids");
	if (ret < 0) {
		perror("Failed to pin scan_pids map");
		goto cleanup;
	}

	// Attach cache_ext_ops to the specific cgroup
	link = bpf_map__attach_cache_ext_ops(skel->maps.sampling_ops, cgroup_fd);
	if (link == NULL) {
		perror("Failed to attach cache_ext_ops to cgroup");
		goto cleanup_unpin;
	}

	// Attach probes
	ret = cache_ext_get_scan_bpf__attach(skel);
	if (ret) {
		perror("Failed to attach BPF programs");
		goto cleanup_unpin;
	}

	// Wait for keyboard input
	printf("Press any key to exit...\n");
	getchar();
	ret = 0;

cleanup_unpin:
	// Unpin scan_pids map
	if (bpf_map__unpin(skel->maps.scan_pids, "/sys/fs/bpf/cache_ext/scan_pids") < 0)
		perror("Failed to unpin scan_pids map");

cleanup:
	close(cgroup_fd);
	bpf_link__destroy(link);
	cache_ext_get_scan_bpf__destroy(skel);
	return ret;
}
