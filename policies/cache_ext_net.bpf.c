#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

struct net_folio_metadata {
    u32 owner_pid;
    u64 last_access_ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 9);
    __type(key, u32);
    __type(value, u64);
} debug_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, s32);
    __type(value, u64);
    __uint(max_entries, 16);
} add_tail_errors SEC(".maps");

struct { 
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64); 
    __type(value, struct net_folio_metadata);
    __uint(max_entries, 1000000);
} folio_metadata_map SEC(".maps");

u64 last_packet_ts = 0;   
u32 active_db_pid = 0; 


#define NET_IDLE_TIMEOUT 5000000000ULL 
#define WORKING_SET_WINDOW 1000000000ULL

static u64 main_list;

static __always_inline void bump_counter(u32 idx) {
    u64 *val = bpf_map_lookup_elem(&debug_counters, &idx);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

static __always_inline void bump_error(s32 err) {
    u64 *val = bpf_map_lookup_elem(&add_tail_errors, &err);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        u64 one = 1;
        bpf_map_update_elem(&add_tail_errors, &err, &one, BPF_ANY);
    }
}

static __always_inline bool is_folio_lru_eligible(struct folio *folio) {
    if (!folio_test_uptodate(folio) || !folio_test_lru(folio))
        return false;
    if (folio_test_dirty(folio) || folio_test_writeback(folio))
        return false;
    if (folio_test_unevictable(folio))
        return false;
    return true;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(net_init, struct mem_cgroup *memcg)
{
    bump_counter(5);
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (!main_list) return -1;
    bpf_printk("cache_ext_net: Created main_list: %llu\n", main_list);
    return 0;
}

// static int bpf_net_evict_cb(int idx, struct cache_ext_list_node *a)
// {
//     u64 now = bpf_ktime_get_ns();
//     bool is_session_active = (now - last_packet_ts) < NET_IDLE_TIMEOUT;

//     u64 key = (u64)a->folio;
//     struct net_folio_metadata *meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
    
//     if (!meta) return CACHE_EXT_EVICT_NODE; 
//     if (meta->owner_pid != active_db_pid) {
//         return CACHE_EXT_EVICT_NODE;
//     }

//     if (is_session_active) {
//         if ((now - meta->last_access_ts) < WORKING_SET_WINDOW) {
//             return CACHE_EXT_CONTINUE_ITER; 
//         }
//     }

//     // active DB page but not recently accessed
//     return CACHE_EXT_EVICT_NODE;
// }

#define PERIOD_NS 100000000ULL // 100ms threshold

static int bpf_net_evict_cb(int idx, struct cache_ext_list_node *a)
{   
    // bpf_printk("cache_ext_net: evaluating folio %p for eviction\n", a->folio);
    // return CACHE_EXT_CONTINUE_ITER; 
    u64 now = bpf_ktime_get_ns();
    u64 key = (u64)a->folio;
    struct net_folio_metadata *meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
    
    if (!meta) return CACHE_EXT_EVICT_NODE; 

    if ((now - meta->last_access_ts) < PERIOD_NS) {
        return CACHE_EXT_CONTINUE_ITER;
    }

    if (active_db_pid == 0) {
         return CACHE_EXT_CONTINUE_ITER; 
    }

    if (meta->owner_pid != active_db_pid) {
        bpf_printk("cache_ext_net: evicting folio %p owned by PID %u (active DB PID: %u)\n", a->folio, meta->owner_pid, active_db_pid);
        return CACHE_EXT_EVICT_NODE;
    }

    bool is_session_active = (now - last_packet_ts) < NET_IDLE_TIMEOUT;
    if (is_session_active) {
        if ((now - meta->last_access_ts) < WORKING_SET_WINDOW) {
            return CACHE_EXT_CONTINUE_ITER; 
        }
    }
    
    bpf_printk("cache_ext_net: evicting folio %p owned by PID %u\n", a->folio, meta->owner_pid);
    return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(net_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
            struct mem_cgroup *memcg)
{
    bump_counter(0);
    // bpf_printk("cache_ext_net: evict_folios called\n");
    bpf_cache_ext_list_iterate(memcg, main_list, bpf_net_evict_cb, eviction_ctx);
}

void BPF_STRUCT_OPS(net_folio_evicted, struct folio *folio) {
    u64 key = (u64)folio;
    bpf_map_delete_elem(&folio_metadata_map, &key);
}

void BPF_STRUCT_OPS(net_folio_added, struct folio *folio) {
    if (!folio->mapping || !folio->mapping->host) {
        bump_counter(1);
        return;
    }
    if (!inode_in_watchlist(folio->mapping->host->i_ino)) {
        bump_counter(2);
        return;
    }

    bump_counter(3);
}

void BPF_STRUCT_OPS(net_folio_accessed, struct folio *folio) {
    bump_counter(8);
    u64 key = (u64)folio;
    struct net_folio_metadata *meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
    if (!meta) {
        if (!folio->mapping || !folio->mapping->host) {
            return;
        }
        if (!inode_in_watchlist(folio->mapping->host->i_ino)) {
            return;
        }
        int ret = bpf_cache_ext_list_add(main_list, folio);
        if (ret) {
            bump_error(ret);
            bump_counter(4);
            if (bpf_cache_ext_list_move(main_list, folio, true) == 0) {
                bump_counter(6); // already in list
            } else {
                bump_counter(7); // not in list / other error
            }
            return;
        }
        struct net_folio_metadata new_meta = {0};
        new_meta.owner_pid = bpf_get_current_pid_tgid() >> 32;
        new_meta.last_access_ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
        return;
    }

    meta->last_access_ts = bpf_ktime_get_ns();
    bpf_cache_ext_list_move(main_list, folio, true);
}

// SEC("kprobe/tcp_sendmsg")
// int trace_tcp_sendmsg(struct pt_regs *ctx)
// {
//     struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
//     if (!sk) return 0;

//     u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num); 

//     if (sport == 9001 || sport == 9002) {
//         last_packet_ts = bpf_ktime_get_ns();
//         active_db_pid = bpf_get_current_pid_tgid() >> 32;
//     }
//     return 0;
// }

SEC("kprobe/tcp_recvmsg") 
int trace_tcp_recvmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num); 

    if (sport == 9001 || sport == 9002) {
        last_packet_ts = bpf_ktime_get_ns();
        active_db_pid = bpf_get_current_pid_tgid() >> 32;
    }
    return 0;
}

SEC(".struct_ops.link")
struct cache_ext_ops net_ops = {
    .init = (void *)net_init,
    .evict_folios = (void *)net_evict_folios,
    .folio_added = (void *)net_folio_added,
    .folio_evicted = (void *)net_folio_evicted,
    .folio_accessed = (void *)net_folio_accessed,
    .admit_folio = (void *)0,
};