// BPF page cache eviction policy

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

struct lfu_folio_metadata {
    u32 access_count;
    u64 last_access_ts;
    u64 prev_access_ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct lfu_folio_metadata);
    __uint(max_entries, 1000000);
} folio_metadata_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 17);
    __type(key, u32);
    __type(value, u64);
} debug_counters SEC(".maps");

static __always_inline void bump_counter(u32 idx)
{
    u64 *val = bpf_map_lookup_elem(&debug_counters, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline bool is_folio_relevant(struct folio *folio)
{
    if (!folio || !folio->mapping || !folio->mapping->host)
        return false;
    return inode_in_watchlist(folio->mapping->host->i_ino);
}

// EVOLVE-BLOCK-START
#include "LLM2.h"
// EVOLVE-BLOCK-END

s32 BPF_STRUCT_OPS_SLEEPABLE(evolved_init, struct mem_cgroup *memcg)
{
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (!main_list)
        return -1;
    return 0;
}

void BPF_STRUCT_OPS(evolved_evict_folios,
                    struct cache_ext_eviction_ctx *eviction_ctx,
                    struct mem_cgroup *memcg)
{
    bump_counter(0);
    struct sampling_options opts = { .sample_size = SAMPLE_SIZE };
    bpf_cache_ext_list_sample(memcg, main_list, bpf_score_fn, &opts,
                              eviction_ctx);
}

void BPF_STRUCT_OPS(evolved_folio_added, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    int ret = bpf_cache_ext_list_add_tail(main_list, folio);
    if (ret != 0) {
        bump_counter(1);
        return;
    }

    u64 key = (u64)folio;
    u64 now = bpf_ktime_get_ns();
    struct lfu_folio_metadata new_meta = {
        .access_count = 1,
        .last_access_ts = now,
        .prev_access_ts = now,
    };
    bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
    bump_counter(2);
}

void BPF_STRUCT_OPS(evolved_folio_accessed, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    u64 key = (u64)folio;
    struct lfu_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta) {
        int ret = bpf_cache_ext_list_add(main_list, folio);
        if (ret != 0)
            bpf_cache_ext_list_move(main_list, folio, false);
        u64 now = bpf_ktime_get_ns();
        struct lfu_folio_metadata new_meta = {
            .access_count = 1,
            .last_access_ts = now,
            .prev_access_ts = now,
        };
        bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
        bump_counter(3);
        return;
    }

    u64 now = bpf_ktime_get_ns();
    meta->prev_access_ts = meta->last_access_ts;
    meta->last_access_ts = now;
    meta->access_count += 1;
    bump_counter(4);
}

void BPF_STRUCT_OPS(evolved_folio_evicted, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    u64 key = (u64)folio;
    bpf_map_delete_elem(&folio_metadata_map, &key);
    bump_counter(5);
}

SEC(".struct_ops.link")
struct cache_ext_ops evolved_ops = {
    .init           = (void *)evolved_init,
    .evict_folios   = (void *)evolved_evict_folios,
    .folio_added    = (void *)evolved_folio_added,
    .folio_evicted  = (void *)evolved_folio_evicted,
    .folio_accessed = (void *)evolved_folio_accessed,
    .admit_folio    = (void *)0,
};
