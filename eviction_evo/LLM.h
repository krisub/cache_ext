// EVOLVE-BLOCK-START
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
    [GF_SEGS_IN]        = { .listener_mask = 0, .ewma_alpha = 200, .rw_size = 4 },
    [GF_SEGS_OUT]       = { .listener_mask = 0, .ewma_alpha = 200, .rw_size = 4 },
    [GF_BYTES_RECEIVED] = { .listener_mask = 0, .ewma_alpha = 200, .rw_size = 4 },
    [GF_BYTES_ACKED]    = { .listener_mask = 0, .ewma_alpha = 200, .rw_size = 4 },
    [GF_CLIENT_TAG]     = { .listener_mask = 0, .ewma_alpha = 200, .rw_size = 4 },
};

// -- Per-folio listener configuration ----------------------------------------
static const struct vulcan_folio_config folio_cfg = {
    .listener_mask = 0,
    .ewma_alpha    = 200,
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
    score = (s64)meta_a->access_count;
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

// EVOLVE-BLOCK-END
