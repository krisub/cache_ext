#ifndef _DIR_WATCHER_H
#define _DIR_WATCHER_H

#include <argp.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define inode_watchlist_map(skel)		((skel)->maps.inode_watchlist)

int initialize_watch_dir_map_tagged(const char *path, int watch_dir_map_fd,
				    bool recursive, __u32 tag)
{
	int ret;
	DIR *dir;
	struct dirent *ent;

	dir = opendir(path);
	if (dir == NULL) {
		perror("Error opening directory");
		return errno;
	}

	while ((ent = readdir(dir)) != NULL) {
		if (strncmp(ent->d_name, ".", 1) == 0 || strncmp(ent->d_name, "..", 2) == 0)
			continue;

		if (strcmp(ent->d_name, ".git") == 0)
			continue;

		char *filename = ent->d_name;
		char *filepath = (char *)malloc(strlen(path) + strlen(filename) + 2);
		sprintf(filepath, "%s/%s", path, filename);

		struct stat sb;
		if (stat(filepath, &sb) == -1) {
			fprintf(stderr, "stat: %s: %s\n", strerror(errno), filepath);
			free(filepath);
			return -1;
		}
		if (S_ISDIR(sb.st_mode)) {
			if (!recursive) {
				free(filepath);
				continue;
			}

			ret = initialize_watch_dir_map_tagged(filepath, watch_dir_map_fd,
							    recursive, tag);
			if (ret < 0) {
				closedir(dir);
				free(filepath);
				return ret;
			}
		}
		free(filepath);

		ret = bpf_map_update_elem(watch_dir_map_fd, &ent->d_ino, &tag, 0);
		if (ret) {
			perror("Failed to update watch_dir map");
			closedir(dir);
			return -1;
		}
	}

	closedir(dir);

	return 0;
}

static inline int initialize_watch_dir_map(const char *path, int watch_dir_map_fd,
					   bool recursive)
{
	return initialize_watch_dir_map_tagged(path, watch_dir_map_fd, recursive, 1);
}

static inline int initialize_dual_watch_dir_maps(const char *path1, const char *path2,
						 int watch_dir_map_fd,
						 __u32 tag1, __u32 tag2)
{
	int ret = initialize_watch_dir_map_tagged(path1, watch_dir_map_fd, true, tag1);
	if (ret)
		return ret;
	return initialize_watch_dir_map_tagged(path2, watch_dir_map_fd, true, tag2);
}

#endif /* _DIR_WATCHER_H */
