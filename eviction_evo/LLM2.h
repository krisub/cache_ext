// EVOLVE-BLOCK-START
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
    score = (s64)meta_a->access_count;

    if (is_last_page_in_file(a->folio)) {
        score += 100000;
    }

    if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) {
        return S64_MAX;
    }
    if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) {
        return S64_MAX;
    }
    return score;
}

// EVOLVE-BLOCK-END
