#ifndef PERSISTENCE_H
#define PERSISTENCE_H

#include "smt.h"
#include "common.h"

#define MAX_SSTABLES_INITIAL 10
#define MEMTABLE_THRESHOLD 1000
#define MAX_KEY_SIZE 256
#define MAX_VALUE_SIZE 1024

typedef struct {
    SMT memtable;            // In-memory SMT for recent writes
    SMT* sstables;           // Array of on-disk SMTs
    size_t sstable_count;    // Number of SSTables
    size_t sstable_capacity; // Capacity of SSTable array
    FILE* wal;               // Write-Ahead Log file handle
    char* collection_path;   // Path to collection storage
    char* collection_name;   // Name of the collection
} PersistenceManager;

// Initialization and cleanup
db_error_t persistence_init(PersistenceManager* pm, const char* collection_path, const char* collection_name);
void persistence_cleanup(PersistenceManager* pm);
db_error_t persistence_load(PersistenceManager* pm);

// CRUD operations
db_error_t persistence_insert(PersistenceManager* pm, const char* key, const char* value);
db_error_t persistence_update(PersistenceManager* pm, const char* key, const char* value);
db_error_t persistence_delete(PersistenceManager* pm, const char* key);
db_error_t persistence_find(PersistenceManager* pm, const char* key, char** value);

// Batch operations
db_error_t persistence_batch_insert(PersistenceManager* pm, const char** keys, const char** values, size_t count);
db_error_t persistence_find_all(PersistenceManager* pm, char*** keys, char*** values, size_t* count);

// Maintenance operations
db_error_t persistence_flush(PersistenceManager* pm);
db_error_t persistence_get_root(PersistenceManager* pm, unsigned char* root_hash);

// Proof operations
db_error_t persistence_generate_proof(PersistenceManager* pm, const char* key, MembershipProof* proof);
db_error_t persistence_verify_proof(PersistenceManager* pm, const char* key, const char* value, 
                                   const MembershipProof* proof, int* valid);

#endif // PERSISTENCE_H