// vulcan_bpf.h -- BPF-compatible listener primitives for kernel-libvulcan.
//
// Standalone, reusable library header.  No BPF map references, no
// policy-specific code.  Any kernel BPF task (eviction, prefetching, etc.)
// can include this file to get listener primitives and configuration types.
//
// Listener types:
//   vulcan_minmax          -- tracks observed min and max
//   vulcan_ewma            -- exponentially weighted moving average (fixed-point)
//   vulcan_avg             -- running arithmetic average
//   vulcan_rolling_window  -- fixed-size circular buffer with windowed average
//
// Configuration:
//   vulcan_feature_config  -- per-feature bitmask selecting which listeners
//                             are active, plus per-listener parameters
//   vulcan_folio_config    -- per-folio listener bitmask + parameters
//
// EWMA uses fixed-point arithmetic scaled by VULCAN_FP_SCALE (1000).
// Alpha values are integers in [0, 1000]: 1000 = alpha=1.0, 100 = 0.1.
//
// Rolling windows have compile-time max VULCAN_MAX_WINDOW (16).
//
// PREREQUISITE: vmlinux.h (or equivalent kernel types) must be included
//               before this header for s64, u64, u32, bool, etc.

#ifndef _VULCAN_BPF_H
#define _VULCAN_BPF_H

// ============================================================================
// Constants
// ============================================================================

#define VULCAN_FP_SCALE   1000
#define VULCAN_MAX_WINDOW 16

// ============================================================================
// Listener bitmask flags  (used in vulcan_feature_config.listener_mask)
// ============================================================================

#define VULCAN_LISTENER_MINMAX  (1U << 0)
#define VULCAN_LISTENER_EWMA    (1U << 1)
#define VULCAN_LISTENER_AVG     (1U << 2)
#define VULCAN_LISTENER_RW      (1U << 3)

#define VULCAN_LISTENER_ALL     (VULCAN_LISTENER_MINMAX | VULCAN_LISTENER_EWMA | \
                                 VULCAN_LISTENER_AVG    | VULCAN_LISTENER_RW)

// ============================================================================
// Per-feature configuration
// ============================================================================

struct vulcan_feature_config {
    u32 listener_mask;   // OR of VULCAN_LISTENER_* flags
    u32 ewma_alpha;      // [0..1000], used when VULCAN_LISTENER_EWMA is set
    u32 rw_size;         // [1..16],   used when VULCAN_LISTENER_RW is set
};

// Per-folio (object-level) listener configuration
struct vulcan_folio_config {
    u32 listener_mask;   // OR of VULCAN_LISTENER_MINMAX, VULCAN_LISTENER_EWMA
    u32 ewma_alpha;      // [0..1000], used when VULCAN_LISTENER_EWMA is set
};

// ============================================================================
// Helpers
// ============================================================================

static __always_inline s64 vulcan_sdiv(s64 a, s64 b)
{
    if (b == 0) return 0;
    bool neg = (a < 0) ^ (b < 0);
    u64 ua = a < 0 ? (u64)(-a) : (u64)a;
    u64 ub = b < 0 ? (u64)(-b) : (u64)b;
    u64 q  = ua / ub;
    return neg ? -(s64)q : (s64)q;
}

// ============================================================================
// MinMax
// ============================================================================

struct vulcan_minmax {
    s64 min_val;
    s64 max_val;
    u32 count;
    u32 _pad;
};

static __always_inline void vulcan_minmax_update(struct vulcan_minmax *mm,
                                                 s64 val)
{
    if (mm->count == 0) {
        mm->min_val = val;
        mm->max_val = val;
    } else {
        if (val < mm->min_val) mm->min_val = val;
        if (val > mm->max_val) mm->max_val = val;
    }
    mm->count++;
}

static __always_inline s64 vulcan_minmax_get_min(const struct vulcan_minmax *mm)
{
    return mm->count ? mm->min_val : 0;
}

static __always_inline s64 vulcan_minmax_get_max(const struct vulcan_minmax *mm)
{
    return mm->count ? mm->max_val : 0;
}

// ============================================================================
// EWMA  (alpha in [0, VULCAN_FP_SCALE])
// ============================================================================

struct vulcan_ewma {
    s64 value;
    u32 initialized;
    u32 _pad;
};

static __always_inline void vulcan_ewma_update(struct vulcan_ewma *e,
                                               s64 val, u32 alpha)
{
    if (!e->initialized) {
        e->value = val;
        e->initialized = 1;
    } else {
        e->value = vulcan_sdiv(
            (s64)alpha * val +
            (s64)(VULCAN_FP_SCALE - alpha) * e->value,
            VULCAN_FP_SCALE);
    }
}

static __always_inline s64 vulcan_ewma_get(const struct vulcan_ewma *e)
{
    return e->initialized ? e->value : 0;
}

// ============================================================================
// Running Average
// ============================================================================

struct vulcan_avg {
    s64 sum;
    u64 count;
};

static __always_inline void vulcan_avg_update(struct vulcan_avg *a, s64 val)
{
    a->sum += val;
    a->count++;
}

static __always_inline s64 vulcan_avg_get(const struct vulcan_avg *a)
{
    return a->count ? vulcan_sdiv(a->sum, (s64)a->count) : 0;
}

// ============================================================================
// Rolling Window  (circular buffer, max size VULCAN_MAX_WINDOW)
// ============================================================================

struct vulcan_rolling_window {
    s64 values[VULCAN_MAX_WINDOW];
    u32 head;
    u32 count;
    s64 sum;
};

static __always_inline void vulcan_rw_update(struct vulcan_rolling_window *rw,
                                             s64 val, u32 window_size)
{
    if (window_size > VULCAN_MAX_WINDOW)
        window_size = VULCAN_MAX_WINDOW;
    if (window_size == 0)
        return;

    u32 idx = rw->head;
    if (idx >= VULCAN_MAX_WINDOW)
        idx = 0;

    if (rw->count >= window_size)
        rw->sum -= rw->values[idx];

    rw->values[idx] = val;
    rw->sum += val;
    rw->head = (idx + 1) % VULCAN_MAX_WINDOW;
    if (rw->count < window_size)
        rw->count++;
}

static __always_inline s64
vulcan_rw_get_latest(const struct vulcan_rolling_window *rw)
{
    if (rw->count == 0) return 0;
    u32 idx = (rw->head + VULCAN_MAX_WINDOW - 1) % VULCAN_MAX_WINDOW;
    if (idx >= VULCAN_MAX_WINDOW) return 0;
    return rw->values[idx];
}

static __always_inline s64
vulcan_rw_get_kth_recent(const struct vulcan_rolling_window *rw, u32 k)
{
    if (k >= rw->count || k >= VULCAN_MAX_WINDOW) return 0;
    u32 idx = (rw->head + VULCAN_MAX_WINDOW - 1 - k) % VULCAN_MAX_WINDOW;
    if (idx >= VULCAN_MAX_WINDOW) return 0;
    return rw->values[idx];
}

static __always_inline s64
vulcan_rw_get_avg(const struct vulcan_rolling_window *rw)
{
    if (rw->count == 0) return 0;
    return vulcan_sdiv(rw->sum, (s64)rw->count);
}

static __always_inline u32
vulcan_rw_get_count(const struct vulcan_rolling_window *rw)
{
    return rw->count;
}

// ============================================================================
// Per-folio metadata  (object-level listeners embedded in each folio entry)
// ============================================================================

struct vulcan_folio_metadata {
    u64 last_access_ts;
    u64 prev_access_ts;
    u32 access_count;
    u32 client_tag; /* 0 = unset; else inode watch tag (DB / workload id) */
    struct vulcan_minmax interval_minmax;
    struct vulcan_ewma   interval_ewma;
};

/*
* interval_minmax is the min and max interval between two accesses.
* interval_ewma is the EWMA of the interval between two accesses.
* low EWMA- frequent access
* high EWMA- rare access
*/

/*

- last access timestamp
- prev access timestamp
- access count
- client tag
- interval_minmax = { .min_val = 0, .max_val = 0, .count = 0, ._pad = 0 }
State for min/max of access intervals:
min_val: smallest interval seen so far
max_val: largest interval seen so far
count: how many interval samples have been incorporated
_pad: padding/alignment field for struct layout

interval_ewma = { .value = 0, .initialized = 0, ._pad = 0 }
State for EWMA of access intervals:
value: current EWMA value
initialized: flag indicating whether EWMA has received its first real sample
_pad: padding/alignment field
(time gap between consecutive accesses to the same object/folio)

*/
static __always_inline struct vulcan_folio_metadata
vulcan_folio_init(u64 now)
{
    struct vulcan_folio_metadata m = {
        .last_access_ts  = now,
        .prev_access_ts  = 0,
        .access_count    = 1,
        .client_tag      = 0,
        .interval_minmax = { .min_val = 0, .max_val = 0, .count = 0, ._pad = 0 },
        .interval_ewma   = { .value = 0, .initialized = 0, ._pad = 0 },
    };
    return m;
}

static __always_inline void
vulcan_folio_on_access(struct vulcan_folio_metadata *meta, u64 now,
                       const struct vulcan_folio_config *cfg)
{
    if (meta->last_access_ts > 0 && meta->access_count > 0) {
        s64 interval = (s64)(now - meta->last_access_ts);
        if (cfg->listener_mask & VULCAN_LISTENER_MINMAX)
            vulcan_minmax_update(&meta->interval_minmax, interval);
        if (cfg->listener_mask & VULCAN_LISTENER_EWMA)
            vulcan_ewma_update(&meta->interval_ewma, interval, cfg->ewma_alpha);
    }
    meta->prev_access_ts = meta->last_access_ts;
    meta->last_access_ts = now;
    meta->access_count++;
}

#endif /* _VULCAN_BPF_H */
