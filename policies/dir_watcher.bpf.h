#ifndef __BPF_DIR_WATCHER_H
#define __BPF_DIR_WATCHER_H

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vmlinux.h"

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* Directory st_ino for resolved watch roots (userspace stat after realpath). */
const volatile __u64 watch_root_ino_1 = 0;
/* 0 = unused (single-DB). Must differ from watch_root_ino_1 in dual mode. */
const volatile __u64 watch_root_ino_2 = 0;

/* Tags stored in inode_watchlist (non-zero). Default 1 and 2 for client1/client2. */
const volatile __u32 client_tag_1 = 1;
const volatile __u32 client_tag_2 = 2;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, 200000);
} inode_watchlist SEC(".maps");

static inline __u32 inode_get_client_tag(u64 inode_no)
{
	__u32 *tp = bpf_map_lookup_elem(&inode_watchlist, &inode_no);

	if (!tp || *tp == 0)
		return 0;
	return *tp;
}

static inline bool inode_in_watchlist(u64 inode_no)
{
	return inode_get_client_tag(inode_no) != 0;
}

/*
 * Classify opens by walking dentry parents: any ancestor directory inode may
 * match a watch root. Avoids bpf_d_path — cache-ext / some 6.6 verifiers reject
 * bpf_d_path for vfs_open's struct path * ("cannot access ptr member mnt...").
 */
static inline __u32 client_tag_from_watch_roots(const struct path *path)
{
	struct dentry *d, *parent;
	struct inode *inode;
	__u64 ino;
	int i;

	if (unlikely(!watch_root_ino_1))
		return 0;

	d = BPF_CORE_READ(path, dentry);
	if (!d)
		return 0;

	for (i = 0; i < 64; i++) {
		inode = BPF_CORE_READ(d, d_inode);
		if (!inode)
			return 0;
		ino = BPF_CORE_READ(inode, i_ino);
		if (ino == watch_root_ino_1)
			return client_tag_1;
		if (watch_root_ino_2 && ino == watch_root_ino_2)
			return client_tag_2;
		parent = BPF_CORE_READ(d, d_parent);
		if (!parent || parent == d)
			return 0;
		d = parent;
	}
	return 0;
}

SEC("fentry/vfs_open")
int BPF_PROG(vfs_open_enter, const struct path *path, struct file *file)
{
	(void)file;

	__u32 tag = client_tag_from_watch_roots(path);
	if (tag == 0)
		return 0;

	struct dentry *dentry = BPF_CORE_READ(path, dentry);
	if (!dentry)
		return 0;
	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	if (!inode)
		return 0;
	u64 inode_no = BPF_CORE_READ(inode, i_ino);

	u32 *ret2 = bpf_map_lookup_elem(&inode_watchlist, &inode_no);
	long err;

	if (ret2 != NULL) {
		err = bpf_map_delete_elem(&inode_watchlist, &inode_no);
		if (err != 0) {
			bpf_printk("Failed to delete inode from inode_watchlist: %ld\n",
				   err);
			return 0;
		}
	}

	err = bpf_map_update_elem(&inode_watchlist, &inode_no, &tag, BPF_ANY);
	if (err != 0) {
		bpf_printk("Failed to add inode to inode_watchlist: %ld\n", err);
		return 0;
	}

	return 0;
}

#endif /* __BPF_DIR_WATCHER_H */
