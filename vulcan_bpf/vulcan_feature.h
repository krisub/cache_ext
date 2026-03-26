// vulcan_feature.h -- Feature dispatch layer for kernel-libvulcan.
//
// Provides vulcan_update_feature() which dispatches to only the listeners
// enabled by the per-feature config bitmask, and accessor functions for
// reading listener state from BPF maps.
//
// PREREQUISITES:
//   1. vmlinux.h and bpf_helpers.h must be included before this header.
//   2. vulcan_bpf.h must be included before this header.
//   3. The policy must declare these BPF maps before including this header:
//        vulcan_gminmax  -- BPF_MAP_TYPE_ARRAY of struct vulcan_minmax
//        vulcan_gewma    -- BPF_MAP_TYPE_ARRAY of struct vulcan_ewma
//        vulcan_grw      -- BPF_MAP_TYPE_ARRAY of struct vulcan_rolling_window
//        vulcan_gavg     -- BPF_MAP_TYPE_ARRAY of struct vulcan_avg

#ifndef _VULCAN_FEATURE_H
#define _VULCAN_FEATURE_H

// ============================================================================
// Feature update -- dispatches based on config bitmask
// ============================================================================

static __always_inline void
vulcan_update_feature(u32 feature_id, s64 value,
                      const struct vulcan_feature_config *cfg)
{
    if (cfg->listener_mask & VULCAN_LISTENER_MINMAX) {
        struct vulcan_minmax *mm = bpf_map_lookup_elem(&vulcan_gminmax, &feature_id);
        if (mm) vulcan_minmax_update(mm, value);
    }

    if (cfg->listener_mask & VULCAN_LISTENER_EWMA) {
        struct vulcan_ewma *ew = bpf_map_lookup_elem(&vulcan_gewma, &feature_id);
        if (ew) vulcan_ewma_update(ew, value, cfg->ewma_alpha);
    }

    if (cfg->listener_mask & VULCAN_LISTENER_RW) {
        struct vulcan_rolling_window *rw = bpf_map_lookup_elem(&vulcan_grw, &feature_id);
        if (rw) vulcan_rw_update(rw, value, cfg->rw_size);
    }

    if (cfg->listener_mask & VULCAN_LISTENER_AVG) {
        struct vulcan_avg *av = bpf_map_lookup_elem(&vulcan_gavg, &feature_id);
        if (av) vulcan_avg_update(av, value);
    }
}

// ============================================================================
// Accessor functions  (safe to call even if listener is not enabled --
//                      returns 0 from uninitialized map entries)
// ============================================================================

static __always_inline s64 vulcan_get_min(u32 fid) {
    struct vulcan_minmax *mm = bpf_map_lookup_elem(&vulcan_gminmax, &fid);
    return mm ? vulcan_minmax_get_min(mm) : 0;
}

static __always_inline s64 vulcan_get_max(u32 fid) {
    struct vulcan_minmax *mm = bpf_map_lookup_elem(&vulcan_gminmax, &fid);
    return mm ? vulcan_minmax_get_max(mm) : 0;
}

static __always_inline s64 vulcan_get_ewma(u32 fid) {
    struct vulcan_ewma *ew = bpf_map_lookup_elem(&vulcan_gewma, &fid);
    return ew ? vulcan_ewma_get(ew) : 0;
}

static __always_inline s64 vulcan_get_avg(u32 fid) {
    struct vulcan_avg *av = bpf_map_lookup_elem(&vulcan_gavg, &fid);
    return av ? vulcan_avg_get(av) : 0;
}

static __always_inline s64 vulcan_get_latest(u32 fid) {
    struct vulcan_rolling_window *rw = bpf_map_lookup_elem(&vulcan_grw, &fid);
    return rw ? vulcan_rw_get_latest(rw) : 0;
}

static __always_inline s64 vulcan_get_kth_recent(u32 fid, u32 k) {
    struct vulcan_rolling_window *rw = bpf_map_lookup_elem(&vulcan_grw, &fid);
    return rw ? vulcan_rw_get_kth_recent(rw, k) : 0;
}

static __always_inline s64 vulcan_get_window_avg(u32 fid) {
    struct vulcan_rolling_window *rw = bpf_map_lookup_elem(&vulcan_grw, &fid);
    return rw ? vulcan_rw_get_avg(rw) : 0;
}

static __always_inline u32 vulcan_get_window_count(u32 fid) {
    struct vulcan_rolling_window *rw = bpf_map_lookup_elem(&vulcan_grw, &fid);
    return rw ? vulcan_rw_get_count(rw) : 0;
}

#endif /* _VULCAN_FEATURE_H */
