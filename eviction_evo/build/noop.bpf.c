#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

static u64 main_list;

s32 BPF_STRUCT_OPS_SLEEPABLE(noop_init, struct mem_cgroup *memcg)
{
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    return main_list ? 0 : -1;
}

void BPF_STRUCT_OPS(noop_evict, struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg)
{
    // do nothing
}

void BPF_STRUCT_OPS(noop_added, struct folio *folio) {}
void BPF_STRUCT_OPS(noop_evicted, struct folio *folio) {}
void BPF_STRUCT_OPS(noop_accessed, struct folio *folio) {}

SEC("kprobe/tcp_recvmsg")
int trace_tcp_recvmsg(struct pt_regs *ctx)
{
    return 0;
}

SEC(".struct_ops.link")
struct cache_ext_ops noop_ops = {
    .init           = (void *)noop_init,
    .evict_folios   = (void *)noop_evict,
    .folio_added    = (void *)noop_added,
    .folio_evicted  = (void *)noop_evicted,
    .folio_accessed = (void *)noop_accessed,
    .admit_folio    = (void *)0,
};
