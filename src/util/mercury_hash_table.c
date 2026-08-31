/*
Copyright (c) 2005-2008, Simon Howard

Permission to use, copy, modify, and/or distribute this software
for any purpose with or without fee is hereby granted, provided
that the above copyright notice and this permission notice appear
in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Hash table implementation */

#include "mercury_hash_table.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct hg_hash_table_entry {
    hg_hash_table_key_t key;
    hg_hash_table_value_t value;
    hg_hash_table_entry_t *next;
    unsigned int hash; /* cached finalized hash, avoids re-hashing keys on
                         * rehash and short-circuits equal_func() calls */
};

struct hg_hash_table {
    hg_hash_table_entry_t **table;
    unsigned int table_size; /* always a power of two */
    unsigned int table_mask; /* table_size - 1, used instead of modulo */
    hg_hash_table_hash_func_t hash_func;
    hg_hash_table_equal_func_t equal_func;
    hg_hash_table_key_free_func_t key_free_func;
    hg_hash_table_value_free_func_t value_free_func;
    unsigned int entries;
    unsigned int threshold; /* entries count at which table is grown */
};

/* Initial table size (power of two), chosen so that small tables (the
 * common case for most callers, e.g. address maps in the NA plugins) do
 * not require an immediate allocation/rehash. */
#define HG_HASH_TABLE_MIN_SIZE  16
/* Grow the table once it is 3/4 full (numerator/denominator kept as
 * integers to avoid floating point math on this hot path). */
#define HG_HASH_TABLE_LOAD_NUM  3
#define HG_HASH_TABLE_LOAD_DEN  4

/* Finalize/mix the user-provided hash value (Murmur3 32-bit finalizer).
 * This is cheap (a handful of ALU ops) but significantly improves the
 * distribution of low-quality hash functions (e.g. identity hashes used
 * by several NA plugins) across the power-of-two table, where only the
 * low bits of the raw hash would otherwise be used to select a bucket. */
static HG_UTIL_INLINE unsigned int
hash_table_hash_mix(unsigned int hash)
{
    hash ^= hash >> 16;
    hash *= 0x85ebca6bU;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35U;
    hash ^= hash >> 16;

    return hash;
}

/* Internal function used to allocate the table on hash table creation
 * and when enlarging the table */
static int
hash_table_allocate_table(hg_hash_table_t *hash_table, unsigned int table_size)
{
    hash_table->table_size = table_size;
    hash_table->table_mask = table_size - 1;
    hash_table->threshold =
        (unsigned int) (((uint64_t) table_size * HG_HASH_TABLE_LOAD_NUM) /
                         HG_HASH_TABLE_LOAD_DEN);

    /* Allocate the table and initialise to NULL for all entries */
    hash_table->table = (hg_hash_table_entry_t **) calloc(
        hash_table->table_size, sizeof(hg_hash_table_entry_t *));
    if (hash_table->table == NULL)
        return 0;

    return 1;
}

/* Free an entry, calling the free functions if there are any registered */
static void
hash_table_free_entry(hg_hash_table_t *hash_table, hg_hash_table_entry_t *entry)
{
    /* If there is a function registered for freeing keys, use it to free
     * the key */
    if (hash_table->key_free_func != NULL)
        hash_table->key_free_func(entry->key);

    /* Likewise with the value */
    if (hash_table->value_free_func != NULL)
        hash_table->value_free_func(entry->value);

    /* Free the data structure */
    free(entry);
}

hg_hash_table_t *
hg_hash_table_new(
    hg_hash_table_hash_func_t hash_func, hg_hash_table_equal_func_t equal_func)
{
    hg_hash_table_t *hash_table;

    /* Allocate a new hash table structure */

    hash_table = (hg_hash_table_t *) malloc(sizeof(hg_hash_table_t));

    if (hash_table == NULL)
        return NULL;

    hash_table->hash_func = hash_func;
    hash_table->equal_func = equal_func;
    hash_table->key_free_func = NULL;
    hash_table->value_free_func = NULL;
    hash_table->entries = 0;

    /* Allocate the table */
    if (!hash_table_allocate_table(hash_table, HG_HASH_TABLE_MIN_SIZE)) {
        free(hash_table);

        return NULL;
    }

    return hash_table;
}

void
hg_hash_table_free(hg_hash_table_t *hash_table)
{
    hg_hash_table_entry_t *rover;
    hg_hash_table_entry_t *next;
    unsigned int i;

    /* Free all entries in all chains */

    for (i = 0; i < hash_table->table_size; ++i) {
        rover = hash_table->table[i];
        while (rover != NULL) {
            next = rover->next;
            hash_table_free_entry(hash_table, rover);
            rover = next;
        }
    }

    /* Free the table */
    free(hash_table->table);

    /* Free the hash table structure */
    free(hash_table);
}

void
hg_hash_table_register_free_functions(hg_hash_table_t *hash_table,
    hg_hash_table_key_free_func_t key_free_func,
    hg_hash_table_value_free_func_t value_free_func)
{
    hash_table->key_free_func = key_free_func;
    hash_table->value_free_func = value_free_func;
}

static int
hash_table_enlarge(hg_hash_table_t *hash_table)
{
    hg_hash_table_entry_t **old_table;
    unsigned int old_table_size;
    hg_hash_table_entry_t *rover;
    hg_hash_table_entry_t *next;
    unsigned int entry_index;
    unsigned int i;

    /* Store a copy of the old table */
    old_table = hash_table->table;
    old_table_size = hash_table->table_size;

    /* Allocate a new, larger table (double the size, still a power of
     * two so indexing can keep using a mask instead of modulo) */
    if (!hash_table_allocate_table(hash_table, old_table_size << 1)) {
        /* Failed to allocate the new table */
        hash_table->table = old_table;
        hash_table->table_size = old_table_size;
        hash_table->table_mask = old_table_size - 1;

        return 0;
    }

    /* Link all entries from all chains into the new table.  The cached
     * hash on each entry is reused directly, so keys do not need to be
     * re-hashed here. */

    for (i = 0; i < old_table_size; ++i) {
        rover = old_table[i];

        while (rover != NULL) {
            next = rover->next;

            /* Find the index into the new table */
            entry_index = rover->hash & hash_table->table_mask;

            /* Link this entry into the chain */
            rover->next = hash_table->table[entry_index];
            hash_table->table[entry_index] = rover;

            /* Advance to next in the chain */
            rover = next;
        }
    }

    /* Free the old table */
    free(old_table);

    return 1;
}

int
hg_hash_table_insert(hg_hash_table_t *hash_table, hg_hash_table_key_t key,
    hg_hash_table_value_t value)
{
    hg_hash_table_entry_t *rover;
    hg_hash_table_entry_t *newentry;
    unsigned int hash, entry_index;

    /* If there are too many items in the table with respect to the table
     * size, the number of hash collisions increases and performance
     * decreases. Enlarge the table size to prevent this happening */

    if (hash_table->entries >= hash_table->threshold) {

        /* Table load factor exceeds threshold */
        if (!hash_table_enlarge(hash_table)) {

            /* Failed to enlarge the table */

            return 0;
        }
    }

    /* Generate the hash of the key and hence the index into the table */
    hash = hash_table_hash_mix(hash_table->hash_func(key));
    entry_index = hash & hash_table->table_mask;

    /* Traverse the chain at this location and look for an existing
     * entry with the same key.  Compare the cached hash first to avoid
     * calling the (potentially expensive) equal_func() needlessly. */
    rover = hash_table->table[entry_index];

    while (rover != NULL) {
        if (rover->hash == hash &&
            hash_table->equal_func(rover->key, key) != 0) {

            /* Same key: overwrite this entry with new data */

            /* If there is a value free function, free the old data
             * before adding in the new data */
            if (hash_table->value_free_func != NULL)
                hash_table->value_free_func(rover->value);

            /* Same with the key: use the new key value and free
             * the old one */
            if (hash_table->key_free_func != NULL)
                hash_table->key_free_func(rover->key);

            rover->key = key;
            rover->value = value;

            /* Finished */
            return 1;
        }
        rover = rover->next;
    }

    /* Not in the hash table yet.  Create a new entry */
    newentry = (hg_hash_table_entry_t *) malloc(sizeof(hg_hash_table_entry_t));

    if (newentry == NULL)
        return 0;

    newentry->key = key;
    newentry->value = value;
    newentry->hash = hash;

    /* Link into the list */
    newentry->next = hash_table->table[entry_index];
    hash_table->table[entry_index] = newentry;

    /* Maintain the count of the number of entries */
    ++hash_table->entries;

    /* Added successfully */
    return 1;
}

hg_hash_table_value_t
hg_hash_table_lookup(hg_hash_table_t *hash_table, hg_hash_table_key_t key)
{
    hg_hash_table_entry_t *rover;
    unsigned int hash, entry_index;

    /* Generate the hash of the key and hence the index into the table */
    hash = hash_table_hash_mix(hash_table->hash_func(key));
    entry_index = hash & hash_table->table_mask;

    /* Walk the chain at this index until the corresponding entry is
     * found */
    rover = hash_table->table[entry_index];

    while (rover != NULL) {
        if (rover->hash == hash &&
            hash_table->equal_func(key, rover->key) != 0) {
            /* Found the entry.  Return the data. */
            return rover->value;
        }
        rover = rover->next;
    }

    /* Not found */
    return HG_HASH_TABLE_NULL;
}

int
hg_hash_table_remove(hg_hash_table_t *hash_table, hg_hash_table_key_t key)
{
    hg_hash_table_entry_t **rover;
    hg_hash_table_entry_t *entry;
    unsigned int hash, entry_index;
    int result;

    /* Generate the hash of the key and hence the index into the table */
    hash = hash_table_hash_mix(hash_table->hash_func(key));
    entry_index = hash & hash_table->table_mask;

    /* Rover points at the pointer which points at the current entry
     * in the chain being inspected.  ie. the entry in the table, or
     * the "next" pointer of the previous entry in the chain.  This
     * allows us to unlink the entry when we find it. */
    result = 0;
    rover = &hash_table->table[entry_index];

    while (*rover != NULL) {
        if ((*rover)->hash == hash &&
            hash_table->equal_func(key, (*rover)->key) != 0) {
            /* This is the entry to remove */
            entry = *rover;

            /* Unlink from the list */
            *rover = entry->next;

            /* Destroy the entry structure */
            hash_table_free_entry(hash_table, entry);

            /* Track count of entries */
            --hash_table->entries;
            result = 1;
            break;
        }

        /* Advance to the next entry */
        rover = &((*rover)->next);
    }

    return result;
}

unsigned int
hg_hash_table_num_entries(hg_hash_table_t *hash_table)
{
    return hash_table->entries;
}

void
hg_hash_table_iterate(
    hg_hash_table_t *hash_table, hg_hash_table_iter_t *iterator)
{
    unsigned int chain;

    iterator->hash_table = hash_table;

    /* Default value of next if no entries are found. */
    iterator->next_entry = NULL;

    /* Find the first entry */
    for (chain = 0; chain < hash_table->table_size; ++chain) {
        if (hash_table->table[chain] != NULL) {
            iterator->next_entry = hash_table->table[chain];
            iterator->next_chain = chain;
            break;
        }
    }
}

int
hg_hash_table_iter_has_more(hg_hash_table_iter_t *iterator)
{
    return iterator->next_entry != NULL;
}

hg_hash_table_value_t
hg_hash_table_iter_next(hg_hash_table_iter_t *iterator)
{
    hg_hash_table_entry_t *current_entry;
    hg_hash_table_t *hash_table;
    hg_hash_table_value_t result;
    unsigned int chain;

    hash_table = iterator->hash_table;

    /* No more entries? */
    if (iterator->next_entry == NULL)
        return HG_HASH_TABLE_NULL;

    /* Result is immediately available */
    current_entry = iterator->next_entry;
    result = current_entry->value;

    /* Find the next entry */
    if (current_entry->next != NULL) {
        /* Next entry in current chain */
        iterator->next_entry = current_entry->next;
    } else {
        /* None left in this chain, so advance to the next chain */
        chain = iterator->next_chain + 1;

        /* Default value if no next chain found */
        iterator->next_entry = NULL;

        while (chain < hash_table->table_size) {
            /* Is there anything in this chain? */
            if (hash_table->table[chain] != NULL) {
                iterator->next_entry = hash_table->table[chain];
                break;
            }

            ++chain;
        }

        iterator->next_chain = chain;
    }

    return result;
}
