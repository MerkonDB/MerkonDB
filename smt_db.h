#ifndef SMT_DB_H
#define SMT_DB_H

#include "smt.h"
#include <time.h>
#include <pthread.h>
#include <jansson.h>

// Configuration
#define MAX_DB_NAME_LEN 64
#define MAX_COLLECTION_NAME_LEN 64
#define DEFAULT_MAX_DATABASES 32
#define DEFAULT_MAX_COLLECTIONS 64
#define MAX_THREAD_WAIT_SEC 5

// Error codes
typedef enum {
    DB_SUCCESS = 0,
    DB_ERROR_NULL_POINTER = -1,
    DB_ERROR_MEMORY_ALLOCATION = -2,
    DB_ERROR_INVALID_PARAMETER = -3,
    DB_ERROR_KEY_NOT_FOUND = -4,
    DB_ERROR_DATABASE_NOT_FOUND = -5,
    DB_ERROR_COLLECTION_NOT_FOUND = -6,
    DB_ERROR_DATABASE_EXISTS = -7,
    DB_ERROR_COLLECTION_EXISTS = -8,
    DB_ERROR_MAX_LIMIT_REACHED = -9,
    DB_ERROR_INVALID_JSON = -10,
    DB_ERROR_CONCURRENT_ACCESS = -11,
    DB_ERROR_DATABASE_CLOSED = -12,
    DB_ERROR_IO_ERROR = -13,
    DB_ERROR_CORRUPTED_DATA = -14
} db_error_t;

// Statistics
typedef struct {
    size_t total_records;
    size_t total_collections;
    time_t created_at;
    size_t total_updates;
    time_t last_modified;
    unsigned char root_hash[HASH_SIZE];
    size_t memory_usage_bytes;
} DatabaseStats;

// Collection
typedef struct {
    char name[MAX_COLLECTION_NAME_LEN];
    SMT tree;
    size_t record_count;
    time_t created_at;
    time_t last_modified;
    pthread_rwlock_t lock;
    int is_open;
} Collection;

// Database
typedef struct {
    char name[MAX_DB_NAME_LEN];
    Collection* collections;
    size_t collection_count;
    size_t collection_capacity;
    DatabaseStats stats;
    pthread_rwlock_t lock;
    int is_open;
} Database;

// Database Manager
typedef struct {
    Database* databases;
    size_t db_count;
    size_t db_capacity;
    pthread_mutex_t lock;
    int is_initialized;
    char persistence_path[1024];
} DatabaseManager;

// Initialization
db_error_t db_manager_init(const char* persistence_path);
db_error_t db_manager_init_with_config(size_t max_databases, size_t max_collections, 
                                      const char* persistence_path);
void db_manager_cleanup();

// Database operations
db_error_t db_create(const char* db_name);
db_error_t db_open(const char* db_name);
db_error_t db_close(const char* db_name);
db_error_t db_drop(const char* db_name);
db_error_t db_exists(const char* db_name, int* exists);
db_error_t db_list(char*** db_names, size_t* count);
db_error_t db_get_stats(const char* db_name, DatabaseStats* stats);

// Collection operations
db_error_t db_create_collection(const char* db_name, const char* collection_name);
db_error_t db_drop_collection(const char* db_name, const char* collection_name);
db_error_t db_list_collections(const char* db_name, char*** collection_names, size_t* count);
db_error_t db_collection_exists(const char* db_name, const char* collection_name, int* exists);

// CRUD operations
db_error_t db_insert(const char* db_name, const char* collection_name,
                    const char* key, const char* value);
db_error_t db_find(const char* db_name, const char* collection_name,
                 const char* key, char** value);
db_error_t db_update(const char* db_name, const char* collection_name,
                    const char* key, const char* value);
db_error_t db_delete(const char* db_name, const char* collection_name,
                    const char* key);

// Batch operations
db_error_t db_batch_insert(const char* db_name, const char* collection_name,
                          const char** keys, const char** values, size_t count);
db_error_t db_find_all(const char* db_name, const char* collection_name,
                      char*** keys, char*** values, size_t* count);

void db_free_list(char** list, size_t count);


// Verification
db_error_t db_get_root_hash(const char* db_name, const char* collection_name,
                          unsigned char* root_hash);
db_error_t db_generate_proof(const char* db_name, const char* collection_name,
                           const char* key, MembershipProof* proof);
db_error_t db_verify_proof(const char* db_name, const char* collection_name,
                         const char* key, const char* value,
                         const MembershipProof* proof, int* valid);

// Persistence
db_error_t db_save(const char* db_name);
db_error_t db_load(const char* db_name);
db_error_t db_save_all();
db_error_t db_load_all();


// Utility
const char* db_error_string(db_error_t error);
db_error_t db_compact(const char* db_name);
db_error_t db_verify_integrity(const char* db_name, json_t** verification_results);
#endif // SMT_DB_H