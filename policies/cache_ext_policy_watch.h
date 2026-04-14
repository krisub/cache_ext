/*
 * Shared watch-path setup for cache_ext policy loaders (single --watch_dir or
 * dual --dual_pair with client1/client2 subdirs). Matches evaluate.py and
 * cache_ext_evolved.c.
 */
#ifndef CACHE_EXT_POLICY_WATCH_H
#define CACHE_EXT_POLICY_WATCH_H

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdbool.h>

#include "dir_watcher.h"

#define CACHE_EXT_DUAL_SUB1 "client1"
#define CACHE_EXT_DUAL_SUB2 "client2"

#define CACHE_EXT_ARG_DUAL_PAIR 1002

/* Returns 0 on success. *dual_out: 1 if --dual_pair mode. */
static inline int cache_ext_resolve_watch_paths(const char *watch_dir,
						const char *dual_pair,
						char path1[PATH_MAX],
						char path2[PATH_MAX],
						int *dual_out)
{
	char root[PATH_MAX];
	char sub1[PATH_MAX + 64];
	char sub2[PATH_MAX + 64];

	if (dual_pair && watch_dir) {
		fprintf(stderr, "Use only one of --watch_dir or --dual_pair\n");
		return -1;
	}
	if (!dual_pair && !watch_dir) {
		fprintf(stderr, "Missing --watch_dir or --dual_pair\n");
		return -1;
	}
	if (dual_pair) {
		if (access(dual_pair, F_OK) != 0) {
			perror(dual_pair);
			return -1;
		}
		if (!realpath(dual_pair, root)) {
			perror("realpath");
			return -1;
		}
		snprintf(sub1, sizeof(sub1), "%s/%s", root, CACHE_EXT_DUAL_SUB1);
		snprintf(sub2, sizeof(sub2), "%s/%s", root, CACHE_EXT_DUAL_SUB2);
		if (access(sub1, F_OK) != 0) {
			fprintf(stderr, "Missing directory: %s\n", sub1);
			return -1;
		}
		if (access(sub2, F_OK) != 0) {
			fprintf(stderr, "Missing directory: %s\n", sub2);
			return -1;
		}
		if (!realpath(sub1, path1) || !realpath(sub2, path2))
			return -1;
		if (strlen(path1) > 128 || strlen(path2) > 128) {
			fprintf(stderr, "watch path too long (>128)\n");
			return -1;
		}
		*dual_out = 1;
		return 0;
	}
	if (access(watch_dir, F_OK) != 0) {
		perror(watch_dir);
		return -1;
	}
	if (!realpath(watch_dir, path1))
		return -1;
	if (strlen(path1) > 128) {
		fprintf(stderr, "watch_dir path too long\n");
		return -1;
	}
	path2[0] = '\0';
	*dual_out = 0;
	return 0;
}

static inline int cache_ext_init_inode_watch_map(int map_fd, const char *path1,
						 const char *path2, int dual,
						 bool recursive)
{
	if (dual)
		return initialize_dual_watch_dir_maps(path1, path2, map_fd, 1, 2);
	return initialize_watch_dir_map(path1, map_fd, recursive);
}

/* st_ino of resolved watch directory roots (dir_watcher.bpf.h). */
static inline int cache_ext_watch_root_stat(const char *path1, const char *path2,
					    int dual,
					    unsigned long long *ino1,
					    unsigned long long *ino2)
{
	struct stat st;

	if (stat(path1, &st) != 0 || !S_ISDIR(st.st_mode))
		return -1;
	*ino1 = (unsigned long long)st.st_ino;
	if (dual) {
		if (stat(path2, &st) != 0 || !S_ISDIR(st.st_mode))
			return -1;
		*ino2 = (unsigned long long)st.st_ino;
	} else {
		*ino2 = 0;
	}
	return 0;
}

#define CACHE_EXT_SET_WATCH_ROOT_INOS(skel, ino1, ino2, is_dual)               \
	do {                                                                   \
		(skel)->rodata->watch_root_ino_1 = (ino1);                       \
		(skel)->rodata->watch_root_ino_2 = (is_dual) ? (ino2) : 0ULL;    \
	} while (0)

#endif /* CACHE_EXT_POLICY_WATCH_H */
