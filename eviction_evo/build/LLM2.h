// =============================================================================
// EVICTION POLICY -- evolved block
// =============================================================================

// -- Tunable constants --------------------------------------------------------
#define SAMPLE_SIZE 20

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

static inline bool is_first_page_in_file(struct folio *folio)
{
    if (folio_test_large(folio) || folio_test_hugetlb(folio)) {
        return false;
    }
    unsigned long long page_index = folio_index(folio);
    return page_index == 0;
}

static s64 bpf_score_fn(struct cache_ext_list_node *a)
{
    s64 score = 0;
    struct lfu_folio_metadata *meta_a;
    u64 key_a = (u64)a->folio;
    meta_a = bpf_map_lookup_elem(&folio_metadata_map, &key_a);
    if (!meta_a) {
        bpf_printk("cache_ext: Failed to get metadata\n");
        return S64_MAX;
    }
    // Use piecewise quadratic scaling with soft saturation at access_count=1000
    // to prevent extreme score divergence while maintaining differentiation
    u64 access_count = meta_a->access_count;
    if (access_count <= 1000) {
        // Quadratic scaling for most common access patterns (0-1000)
        score = (s64)(access_count * access_count);
    } else {
        // Linear scaling beyond 1000 to prevent pathological over-protection
        // score = 1000000 + (access_count - 1000) * 500
        score = 1000000 + (s64)((access_count - 1000) * 500);
    }

    // Apply multiplicative boundary scaling: hot boundaries get amplified protection
    if (is_last_page_in_file(a->folio)) {
        // 1.5x multiplier for last pages (most critical for sequential access)
        score = score + (score >> 1);  // score * 1.5
    } else if (is_first_page_in_file(a->folio)) {
        // 1.2x multiplier for first pages (important but less than last)
        score = score + (score >> 2) + (score >> 4);  // score * 1.1875 ≈ 1.2
    }

    if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) {
        return S64_MAX;
    }
    if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) {
        return S64_MAX;
    }
    return score;
}
