#ifndef _VULCAN_FEATURE_H
#define _VULCAN_FEATURE_H

/*
 * Feature dispatch/accessor helpers.
 *
 * Required from includer before this header:
 * - VULCAN_NUM_GLOBAL_FEATURES
 * - maps: vulcan_gminmax, vulcan_gewma, vulcan_grw, vulcan_gavg
 * - enum feature ids compatible with [0, VULCAN_NUM_GLOBAL_FEATURES)
 * - struct vulcan_feature_config + listener helpers from vulcan_bpf.h
 */

static __always_inline void
vulcan_update_feature(u32 feature_id, s64 raw_value,
                      const struct vulcan_feature_config *cfg)
{
    if (!cfg || feature_id >= VULCAN_NUM_GLOBAL_FEATURES)
        return;

    if (cfg->listener_mask & VULCAN_LISTENER_MINMAX) {
        struct vulcan_minmax *mm = bpf_map_lookup_elem(&vulcan_gminmax, &feature_id);
        if (mm)
            vulcan_minmax_update(mm, raw_value);
    }

    if (cfg->listener_mask & VULCAN_LISTENER_EWMA) {
        struct vulcan_ewma *ew = bpf_map_lookup_elem(&vulcan_gewma, &feature_id);
        if (ew)
            vulcan_ewma_update(ew, raw_value, cfg->ewma_alpha);
    }

    if (cfg->listener_mask & VULCAN_LISTENER_AVG) {
        struct vulcan_avg *avg = bpf_map_lookup_elem(&vulcan_gavg, &feature_id);
        if (avg)
            vulcan_avg_update(avg, raw_value);
    }

    if (cfg->listener_mask & VULCAN_LISTENER_RW) {
        struct vulcan_rolling_window *rw =
            bpf_map_lookup_elem(&vulcan_grw, &feature_id);
        if (rw)
            vulcan_rw_update(rw, raw_value, cfg->rw_size);
    }
}

static __always_inline s64 vulcan_get_min(u32 feature_id)
{
    struct vulcan_minmax *mm;
    if (feature_id >= VULCAN_NUM_GLOBAL_FEATURES)
        return 0;
    mm = bpf_map_lookup_elem(&vulcan_gminmax, &feature_id);
    return mm ? vulcan_minmax_get_min(mm) : 0;
}

static __always_inline s64 vulcan_get_max(u32 feature_id)
{
    struct vulcan_minmax *mm;
    if (feature_id >= VULCAN_NUM_GLOBAL_FEATURES)
        return 0;
    mm = bpf_map_lookup_elem(&vulcan_gminmax, &feature_id);
    return mm ? vulcan_minmax_get_max(mm) : 0;
}

static __always_inline s64 vulcan_get_ewma(u32 feature_id)
{
    struct vulcan_ewma *ew;
    if (feature_id >= VULCAN_NUM_GLOBAL_FEATURES)
        return 0;
    ew = bpf_map_lookup_elem(&vulcan_gewma, &feature_id);
    return ew ? vulcan_ewma_get(ew) : 0;
}

static __always_inline s64 vulcan_get_avg(u32 feature_id)
{
    struct vulcan_avg *avg;
    if (feature_id >= VULCAN_NUM_GLOBAL_FEATURES)
        return 0;
    avg = bpf_map_lookup_elem(&vulcan_gavg, &feature_id);
    return avg ? vulcan_avg_get(avg) : 0;
}

static __always_inline s64 vulcan_get_latest(u32 feature_id)
{
    struct vulcan_rolling_window *rw;
    if (feature_id >= VULCAN_NUM_GLOBAL_FEATURES)
        return 0;
    rw = bpf_map_lookup_elem(&vulcan_grw, &feature_id);
    return rw ? vulcan_rw_get_latest(rw) : 0;
}

static __always_inline s64 vulcan_get_kth_recent(u32 feature_id, u32 k)
{
    struct vulcan_rolling_window *rw;
    if (feature_id >= VULCAN_NUM_GLOBAL_FEATURES)
        return 0;
    rw = bpf_map_lookup_elem(&vulcan_grw, &feature_id);
    return rw ? vulcan_rw_get_kth_recent(rw, k) : 0;
}

static __always_inline s64 vulcan_get_window_avg(u32 feature_id)
{
    struct vulcan_rolling_window *rw;
    if (feature_id >= VULCAN_NUM_GLOBAL_FEATURES)
        return 0;
    rw = bpf_map_lookup_elem(&vulcan_grw, &feature_id);
    return rw ? vulcan_rw_get_avg(rw) : 0;
}

static __always_inline u32 vulcan_get_window_count(u32 feature_id)
{
    struct vulcan_rolling_window *rw;
    if (feature_id >= VULCAN_NUM_GLOBAL_FEATURES)
        return 0;
    rw = bpf_map_lookup_elem(&vulcan_grw, &feature_id);
    return rw ? vulcan_rw_get_count(rw) : 0;
}

#endif /* _VULCAN_FEATURE_H */