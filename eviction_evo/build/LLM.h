// =============================================================================
// EVICTION POLICY -- evolved block (limited context)
// =============================================================================
//
// Expected symbols from includer:
// - Types/functions: struct folio, struct address_space, struct cache_ext_list_node,
//   i_size_read(), folio_index(), folio_test_*(), bpf_map_lookup_elem()
// - Constants/types: VULCAN_NUM_GLOBAL_FEATURES, GF_*, u64, s64
// - Map: folio_metadata_map
//
// bpf_score_fn matches policies/cache_ext_sampling.bpf.c (LFU + LevelDB guard):
//   meta field is access_count (vulcan) vs accesses (sampling) — same role.

// Per-client_tag: initial_vulcan_split.c calls vulcan_tag_update_feature(..., &gf_configs[i])
// for each GF_* with non-zero listener_mask (kprobe for TCP rows; folio hooks for tag).
//
// Listener choice — ALREADY IMPLEMENTED: set .listener_mask to any OR of flags from
// vulcan_bpf.h (each bit turns on that backend for this GF_* row):
//   VULCAN_LISTENER_MINMAX  — min/max over observed raw values (vulcan_tag_get_min/max)
//   VULCAN_LISTENER_EWMA    — EWMA of raw stream (needs .ewma_alpha [0..1000])
//   VULCAN_LISTENER_AVG     — running average (vulcan_tag_get_avg)
//   VULCAN_LISTENER_RW      — rolling window of last N samples (needs .rw_size 1..16;
//                              vulcan_tag_get_latest / window_avg / kth_recent)
//   VULCAN_LISTENER_ALL     — shorthand for all four at once
// You can combine, e.g. VULCAN_LISTENER_EWMA | VULCAN_LISTENER_RW.
//
// Params: .ewma_alpha used only if EWMA bit set; .rw_size only if RW bit set.

// Client tag + TCP “packets” (segs in/out) + bytes in/out — evolve listener_mask + params
static const struct vulcan_feature_config gf_configs[VULCAN_NUM_GLOBAL_FEATURES] = {
    [GF_SEGS_IN]        = { .listener_mask = VULCAN_LISTENER_EWMA | VULCAN_LISTENER_RW, .ewma_alpha = 250, .rw_size = 8 },
    [GF_SEGS_OUT]       = { .listener_mask = VULCAN_LISTENER_EWMA | VULCAN_LISTENER_RW, .ewma_alpha = 250, .rw_size = 8 },
    [GF_BYTES_RECEIVED] = { .listener_mask = VULCAN_LISTENER_EWMA | VULCAN_LISTENER_MINMAX, .ewma_alpha = 270, .rw_size = 8 },
    [GF_BYTES_ACKED]    = { .listener_mask = VULCAN_LISTENER_EWMA | VULCAN_LISTENER_MINMAX, .ewma_alpha = 330, .rw_size = 8 },
    [GF_CLIENT_TAG]     = { .listener_mask = VULCAN_LISTENER_EWMA | VULCAN_LISTENER_RW, .ewma_alpha = 250, .rw_size = 8 },
};

// -- Per-folio listener configuration ----------------------------------------
static const struct vulcan_folio_config folio_cfg = {
    .listener_mask = VULCAN_LISTENER_EWMA,
    .ewma_alpha    = 300,
};

// -- Tunable constants --------------------------------------------------------
#define SAMPLE_SIZE 20

#ifndef INT64_MAX
#define INT64_MAX ((s64)9223372036854775807LL)
#endif

enum App {
    GENERIC_APP,
    LEVELDB,
};

const int APP_TYPE = GENERIC_APP;

static u64 main_list;

static inline bool is_last_page_in_file(struct folio *folio)
{
    struct address_space *mapping = folio->mapping;
    if (!mapping) {
        return false;
    }
    struct inode *inode = mapping->host;
    if (!inode) {
        return false;
    }
    if (folio_test_large(folio) || folio_test_hugetlb(folio)) {
        bpf_printk("cache_ext: Hugepages not supported\n");
        return false;
    }
    unsigned long long file_size = i_size_read(inode);
    unsigned long long page_index = folio_index(folio);
    unsigned long long page_size = 4096;
    unsigned long long last_page_index =
        (file_size + page_size - 1) / page_size - 1;
    return page_index == last_page_index;
}

static s64 bpf_score_fn(struct cache_ext_list_node *a)
{
    s64 score = 0;
    struct vulcan_folio_metadata *meta_a;
    u64 key_a = (u64)a->folio;
    meta_a = bpf_map_lookup_elem(&folio_metadata_map, &key_a);
    if (!meta_a) {
        bpf_printk("cache_ext: Failed to get metadata\n");
        return INT64_MAX;
    }

    // Base score: access frequency (primary signal)
    u64 base_score = meta_a->access_count;

    // Network activity boost: protect pages from high-throughput clients
    u64 client_tag = meta_a->client_tag;
    u64 net_boost = 0;

    if (client_tag != 0) {
        // Get historical peak and current EWMA for bytes
        u64 max_bytes_recv = vulcan_tag_get_max(client_tag, GF_BYTES_RECEIVED);
        u64 max_bytes_acked = vulcan_tag_get_max(client_tag, GF_BYTES_ACKED);
        u64 ewma_bytes_recv = vulcan_tag_get_ewma(client_tag, GF_BYTES_RECEIVED);
        u64 ewma_bytes_acked = vulcan_tag_get_ewma(client_tag, GF_BYTES_ACKED);

        // Get segment trends
        u64 ewma_segs_in = vulcan_tag_get_ewma(client_tag, GF_SEGS_IN);
        u64 ewma_segs_out = vulcan_tag_get_ewma(client_tag, GF_SEGS_OUT);

        // Scale down to prevent overflow
        u64 peak_bytes = (max_bytes_recv >> 12) + (max_bytes_acked >> 12);
        u64 ewma_bytes = (ewma_bytes_recv >> 12) + (ewma_bytes_acked >> 12);
        u64 seg_trend = (ewma_segs_in + ewma_segs_out) >> 2;

        // Calculate activity ratio: current EWMA relative to historical peak
        // Only apply boost when ratio > 50% (client is currently hot)
        if (peak_bytes > 0 && (ewma_bytes << 1) > peak_bytes) {
            // Client is active (EWMA > 50% of peak)
            // Calculate ratio multiplier: 1 + (ewma / peak)
            // Use safe division: multiply by 1000, divide, then scale back
            u64 ratio_scaled = (ewma_bytes * 1000) / peak_bytes;

            // Base network boost: peak (40%) + EWMA (40%) + segments (20%)
            u64 base_net = (peak_bytes << 1) + (ewma_bytes << 1) + seg_trend;

            // Apply dynamic multiplier: boost * (1 + ratio)
            // ratio_scaled is in [500..1000+] since we checked ewma > 50% of peak
            // Multiply by (1000 + ratio_scaled) / 1000
            net_boost = (base_net * (1000 + ratio_scaled)) / 1000;
        }
    }

    // Combine base score with network boost
    // Give network activity more weight: shift by 2 instead of 4
    u64 combined = base_score + (net_boost >> 2);

    // Folio interval EWMA: recent access pattern
    u64 interval_ewma = meta_a->interval_ewma.value;
    // Lower interval = more frequent recent access = protect more
    if (interval_ewma > 0 && interval_ewma < 500000ULL) {
        // Simple inverse boost: more frequent access (lower interval) = higher score
        u64 recency_boost = (500000ULL - interval_ewma) >> 10;
        combined += recency_boost;
    }

    score = (s64)combined;

    if (APP_TYPE == LEVELDB) {
        bool is_last_page = is_last_page_in_file(a->folio);
        if (is_last_page) {
            score += 100000;
        }
    }

    if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) {
        return INT64_MAX;
    }
    if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) {
        return INT64_MAX;
    }
    return score;
}
