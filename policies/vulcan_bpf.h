// vulcan_bpf.h — BPF-compatible listener primitives for kernel-libvulcan.
//
// Provides four listener types that maintain running statistics over a
// stream of integer values.  All arithmetic is integer-only (no floats).
//
// Listener types:
//   vulcan_minmax          — tracks observed min and max
//   vulcan_ewma            — exponentially weighted moving average (fixed-point)
//   vulcan_avg             — running arithmetic average
//   vulcan_rolling_window  — fixed-size circular buffer with windowed average
//
// EWMA uses fixed-point arithmetic scaled by VULCAN_FP_SCALE (1000).
// Alpha values are integers in [0, 1000]: 1000 ≡ alpha=1.0, 100 ≡ 0.1.
//
// Rolling windows have compile-time max VULCAN_MAX_WINDOW (16).
// The runtime window size is passed to vulcan_rw_update().
//
// PREREQUISITE: vmlinux.h must be included before this header.

#ifndef _VULCAN_BPF_H
#define _VULCAN_BPF_H

#define VULCAN_FP_SCALE   1000
#define VULCAN_MAX_WINDOW 16

// BPF does not support signed division.  This helper handles the sign
// manually so the compiler only emits unsigned udiv.
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
// EWMA  (alpha ∈ [0, VULCAN_FP_SCALE])
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

#endif /* _VULCAN_BPF_H */
