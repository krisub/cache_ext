#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

u64 total_tx_bytes = 0; // total transmitted bytes
u64 last_packet_ts = 0; // timestamp of the last packet in nanoseconds

// threshold: 50 milliseconds (in nanoseconds)
// if a packet was sent within this window, we consider the network "busy"
#define NET_BUSY_THRESHOLD_NS 50000000ULL 

SEC("tracepoint/net/net_dev_xmit")
int handle_net_xmit(struct trace_event_raw_net_dev_xmit *ctx)
{
    // update the total bytes
    __sync_fetch_and_add(&total_tx_bytes, ctx->len);
    
    // and timestamp of the packet
    last_packet_ts = bpf_ktime_get_ns();
    
    return 0;
}

static inline bool is_folio_relevant(struct folio *folio) {
    if (!folio || !folio->mapping || !folio->mapping->host)
        return false;
    return inode_in_watchlist(folio->mapping->host->i_ino);
}

static u64 main_list;

s32 BPF_STRUCT_OPS_SLEEPABLE(net_init, struct mem_cgroup *memcg)
{
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (main_list == 0) return -1;
    bpf_printk("cache_ext_net: Init. Starting monitoring.\n");
    return 0;
}

static int bpf_net_evict_cb(int idx, struct cache_ext_list_node *a)
{
    u64 now = bpf_ktime_get_ns();
    u64 time_diff = now - last_packet_ts;

    // check if network is busy (activity within the last 50ms)
    if (time_diff < NET_BUSY_THRESHOLD_NS) {
        bpf_printk("cache_ext_net: Network busy (last pkt %llu ms ago). Skipping eviction.\n", 
                        (u64)time_diff / 1000000ULL);
        // skip this page
        return CACHE_EXT_CONTINUE_ITER;
    }
    
    if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
        return CACHE_EXT_CONTINUE_ITER;

    if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
        return CACHE_EXT_CONTINUE_ITER;

    // if network is not busy: FIFO
    return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(net_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
            struct mem_cgroup *memcg)
{
    bpf_cache_ext_list_iterate(memcg, main_list, bpf_net_evict_cb, eviction_ctx);
}

void BPF_STRUCT_OPS(net_folio_evicted, struct folio *folio) {}

void BPF_STRUCT_OPS(net_folio_added, struct folio *folio) {
    if (!is_folio_relevant(folio))
        return;
    bpf_cache_ext_list_add_tail(main_list, folio);
}

SEC(".struct_ops.link")
struct cache_ext_ops net_ops = {
    .init = (void *)net_init,
    .evict_folios = (void *)net_evict_folios,
    .folio_added = (void *)net_folio_added,
    .folio_evicted = (void *)net_folio_evicted,
    .folio_accessed = (void *)0,
    .admit_folio = (void *)0,
};