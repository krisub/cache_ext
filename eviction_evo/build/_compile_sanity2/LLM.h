// =============================================================================
// EVICTION POLICY -- evolved block (limited context)
// =============================================================================
//
// Expected symbols from includer:
// - Types/functions: struct folio, struct address_space, struct cache_ext_list_node,
//   i_size_read(), folio_index(), folio_test_*(), bpf_map_lookup_elem()
// - Constants/types: S64_MAX, VULCAN_NUM_GLOBAL_FEATURES, GF_*, u64, s64
// - Map: folio_metadata_map
// - Per-tag accessor: vulcan_tag_get_ewma(client_tag, GF_xxx)

// -- Per-feature listener configuration --------------------------------------
// Baseline: all disabled (pure LFU, no network overhead). Evolution can enable
// listeners for vulcan_get_* accessors in bpf_score_fn.
static const struct vulcan_feature_config gf_configs[VULCAN_NUM_GLOBAL_FEATURES] = {
    [GF_SRTT_US]        = { .listener_mask = 0 },
    [GF_MDEV_US]        = { .listener_mask = 0 },
    [GF_SND_CWND]       = { .listener_mask = 0 },
    [GF_SND_SSTHRESH]   = { .listener_mask = 0 },
    [GF_RCV_WND]        = { .listener_mask = 0 },
    [GF_PACKETS_OUT]    = { .listener_mask = 0 },
    [GF_TOTAL_RETRANS]  = { .listener_mask = 0 },
    [GF_RETRANS_OUT]    = { .listener_mask = 0 },
    [GF_LOST]           = { .listener_mask = 0 },
    [GF_SEGS_IN]        = { .listener_mask = 0 },
    [GF_SEGS_OUT]       = { .listener_mask = 0 },
    [GF_DELIVERED]      = { .listener_mask = 0 },
    [GF_BYTES_RECEIVED] = { .listener_mask = 0 },
    [GF_BYTES_ACKED]    = { .listener_mask = 0 },
    [GF_INTER_ARRIVAL]  = { .listener_mask = 0 },
    [GF_RECV_COUNT]     = { .listener_mask = 0 },
    [GF_CLIENT_TAG]     = { .listener_mask = 0 },
};

// -- Per-folio listener configuration ----------------------------------------
// Baseline: disabled. Evolution can enable for interval-based scoring.
static const struct vulcan_folio_config folio_cfg = {
    .listener_mask = 0,
    .ewma_alpha    = 200,
};

// -- Tunable constants --------------------------------------------------------
#define SAMPLE_SIZE 20  // Candidates per eviction slot (same as cache_ext_sampling)

static u64 main_list;

// LevelDB: index block is at end of file; protect last page (same as sampling).
static inline bool is_last_page_in_file(struct folio *folio)
{
    struct address_space *mapping = folio->mapping;
    if (!mapping || !mapping->host)
        return false;
    if (folio_test_large(folio) || folio_test_hugetlb(folio))
        return false;
    unsigned long long file_size = i_size_read(mapping->host);
    unsigned long long page_index = folio_index(folio);
    unsigned long long page_size = 4096;
    unsigned long long last_page_index =
        (file_size + page_size - 1) / page_size - 1;
    return page_index == last_page_index;
}

/*
 * Baseline: pure LFU (mimics cache_ext_sampling.bpf.c bpf_lfu_score_fn).
 * Kernel picks LOWEST score in each batch. S64_MAX = never prefer as victim.
 * Evolution can add vulcan_get_* calls and protection rules.
 */
static s64 bpf_score_fn(struct cache_ext_list_node *node)
{
    struct folio *folio = node->folio;
    if (!folio)
        return S64_MAX;

    if (folio_test_dirty(folio) || folio_test_writeback(folio))
        return S64_MAX;
    if (!folio_test_uptodate(folio) || !folio_test_lru(folio))
        return S64_MAX;

    u64 key = (u64)folio;
    struct vulcan_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);
    if (!meta)
        return S64_MAX;

    s64 score = (s64)meta->access_count;

    /* Per-DB network signal: reuse client_tag as DB id. */
    if (meta->client_tag) {
        s64 srtt_ewma = vulcan_tag_get_ewma(meta->client_tag, GF_SRTT_US);
        s64 retrans_ewma = vulcan_tag_get_ewma(meta->client_tag, GF_RETRANS_OUT);

        if (srtt_ewma > 0)
            score += (srtt_ewma >> 10);
        if (retrans_ewma > 0)
            score += (retrans_ewma << 6);
    }

    /* LevelDB: protect index block (last page of file) */
    if (is_last_page_in_file(folio))
        score += 100000;

    return score;
}
