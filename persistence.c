#include "persistence.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/evp.h>

static db_error_t write_wal(PersistenceManager* pm, const char* operation, const char* key, const char* value) {
    if (!pm || !operation || !key) {
        return DB_ERROR_NULL_POINTER;
    }

    if (!pm->wal) {
        char wal_path[2048];
        snprintf(wal_path, sizeof(wal_path), "%s/%s.wal", pm->collection_path, pm->collection_name);
        pm->wal = fopen(wal_path, "a");
        if (!pm->wal) {
            return DB_ERROR_IO_ERROR;
        }
    }

    if (fprintf(pm->wal, "%s %s %s\n", operation, key, value ? value : "NULL") < 0) {
        return DB_ERROR_IO_ERROR;
    }
    fflush(pm->wal);
    return DB_SUCCESS;
}

static db_error_t replay_wal(PersistenceManager* pm) {
    if (!pm) {
        return DB_ERROR_NULL_POINTER;
    }

    char wal_path[2048];
    snprintf(wal_path, sizeof(wal_path), "%s/%s.wal", pm->collection_path, pm->collection_name);
    
    FILE* fp = fopen(wal_path, "r");
    if (!fp) {
        return DB_SUCCESS; // No WAL to replay is not an error
    }

    char operation[16] = {0};
    char key[MAX_KEY_SIZE] = {0};
    char value[MAX_VALUE_SIZE] = {0};
    
    while (fscanf(fp, "%15s %255s %1023[^\n]", operation, key, value) == 3) {
        // Handle NULL values
        if (strcmp(value, "NULL") == 0) {
            value[0] = '\0';
        }

        if (strcmp(operation, "INSERT") == 0 || strcmp(operation, "UPDATE") == 0) {
            smt_error_t err = smt_insert(&pm->memtable, key, value[0] ? value : NULL);
            if (err != SMT_SUCCESS) {
                fclose(fp);
                return (db_error_t)err;
            }
        } 
        else if (strcmp(operation, "DELETE") == 0) {
            smt_error_t err = smt_delete(&pm->memtable, key);
            if (err != SMT_SUCCESS && err != SMT_ERROR_KEY_NOT_FOUND) {
                fclose(fp);
                return (db_error_t)err;
            }
        }
        
        // Clear buffers for next iteration
        memset(operation, 0, sizeof(operation));
        memset(key, 0, sizeof(key));
        memset(value, 0, sizeof(value));
    }

    fclose(fp);
    return DB_SUCCESS;
}

db_error_t persistence_init(PersistenceManager* pm, const char* collection_path, const char* collection_name) {
    if (!pm || !collection_path || !collection_name) {
        return DB_ERROR_NULL_POINTER;
    }

    // Initialize memtable
    memset(pm, 0, sizeof(PersistenceManager));
    smt_error_t smt_err = smt_init(&pm->memtable);
    if (smt_err != SMT_SUCCESS) {
        return (db_error_t)smt_err;
    }

    // Initialize SSTables array
    pm->sstable_capacity = MAX_SSTABLES_INITIAL;
    pm->sstables = malloc(pm->sstable_capacity * sizeof(SMT));
    if (!pm->sstables) {
        smt_cleanup(&pm->memtable);
        return DB_ERROR_MEMORY_ALLOCATION;
    }
    pm->sstable_count = 0;

    // Store paths
    pm->collection_path = strdup(collection_path);
    pm->collection_name = strdup(collection_name);
    if (!pm->collection_path || !pm->collection_name) {
        free(pm->collection_path);
        free(pm->collection_name);
        free(pm->sstables);
        smt_cleanup(&pm->memtable);
        return DB_ERROR_MEMORY_ALLOCATION;
    }

    // Create directory if it doesn't exist - with proper error handling
    if (mkdir(collection_path, 0755) == -1) {
        if (errno != EEXIST) {
            // If directory doesn't exist and we can't create it
            persistence_cleanup(pm);
            return DB_ERROR_IO_ERROR;
        }
        // Directory already exists, check if it's accessible
        if (access(collection_path, R_OK | W_OK | X_OK) != 0) {
            persistence_cleanup(pm);
            return DB_ERROR_IO_ERROR;
        }
    }

    // Initialize WAL
    char wal_path[2048];
    snprintf(wal_path, sizeof(wal_path), "%s/%s.wal", collection_path, collection_name);
    pm->wal = fopen(wal_path, "a");
    if (!pm->wal) {
        persistence_cleanup(pm);
        return DB_ERROR_IO_ERROR;
    }

    // Load existing data
    return persistence_load(pm);
}

db_error_t persistence_load(PersistenceManager* pm) {
    if (!pm) {
        return DB_ERROR_NULL_POINTER;
    }

    // Load existing SSTables
    for (size_t i = 0; ; i++) {
        char sstable_path[2048];
        snprintf(sstable_path, sizeof(sstable_path), "%s/sstable_%zu.dat", pm->collection_path, i);

        FILE* fp = fopen(sstable_path, "rb");
        if (!fp) {
            break; // No more SSTables
        }

        // Resize SSTables array if needed
        if (pm->sstable_count >= pm->sstable_capacity) {
            size_t new_capacity = pm->sstable_capacity * 2;
            SMT* new_sstables = realloc(pm->sstables, new_capacity * sizeof(SMT));
            if (!new_sstables) {
                fclose(fp);
                return DB_ERROR_MEMORY_ALLOCATION;
            }
            pm->sstables = new_sstables;
            pm->sstable_capacity = new_capacity;
        }

        // Initialize and deserialize SSTable
        smt_init(&pm->sstables[pm->sstable_count]);
        smt_error_t err = smt_deserialize(&pm->sstables[pm->sstable_count], fp);
        fclose(fp);

        if (err != SMT_SUCCESS) {
            smt_cleanup(&pm->sstables[pm->sstable_count]);
            return (db_error_t)err;
        }

        pm->sstable_count++;
    }

    // Replay WAL to rebuild memtable
    return replay_wal(pm);
}

db_error_t persistence_insert(PersistenceManager* pm, const char* key, const char* value) {
    if (!pm || !key) {
        return DB_ERROR_NULL_POINTER;
    }

    // Write to WAL first
    db_error_t wal_err = write_wal(pm, "INSERT", key, value);
    if (wal_err != DB_SUCCESS) {
        return wal_err;
    }

    // Update memtable
    smt_error_t smt_err = smt_insert(&pm->memtable, key, value);
    if (smt_err != SMT_SUCCESS) {
        return (db_error_t)smt_err;
    }

    // Check if we need to flush
    if (pm->memtable.total_elements >= MEMTABLE_THRESHOLD) {
        return persistence_flush(pm);
    }

    return DB_SUCCESS;
}

db_error_t persistence_update(PersistenceManager* pm, const char* key, const char* value) {
    if (!pm || !key) {
        return DB_ERROR_NULL_POINTER;
    }

    // Write to WAL first
    db_error_t wal_err = write_wal(pm, "UPDATE", key, value);
    if (wal_err != DB_SUCCESS) {
        return wal_err;
    }

    // Update memtable
    smt_error_t smt_err = smt_insert(&pm->memtable, key, value);
    if (smt_err != SMT_SUCCESS) {
        return (db_error_t)smt_err;
    }

    // Check if we need to flush
    if (pm->memtable.total_elements >= MEMTABLE_THRESHOLD) {
        return persistence_flush(pm);
    }

    return DB_SUCCESS;
}

db_error_t persistence_delete(PersistenceManager* pm, const char* key) {
    if (!pm || !key) {
        return DB_ERROR_NULL_POINTER;
    }

    // Write to WAL first
    db_error_t wal_err = write_wal(pm, "DELETE", key, NULL);
    if (wal_err != DB_SUCCESS) {
        return wal_err;
    }

    // Update memtable
    smt_error_t smt_err = smt_delete(&pm->memtable, key);
    if (smt_err != SMT_SUCCESS && smt_err != SMT_ERROR_KEY_NOT_FOUND) {
        return (db_error_t)smt_err;
    }

    // Check if we need to flush
    if (pm->memtable.total_elements >= MEMTABLE_THRESHOLD) {
        return persistence_flush(pm);
    }

    return DB_SUCCESS;
}

db_error_t persistence_find(PersistenceManager* pm, const char* key, char** value) {
    if (!pm || !key || !value) {
        return DB_ERROR_NULL_POINTER;
    }

    *value = NULL;

    // First check memtable
    smt_error_t err = smt_lookup(&pm->memtable, key, value);
    if (err == SMT_SUCCESS) {
        return DB_SUCCESS;
    }

    // Then check SSTables (newest to oldest)
    for (size_t i = pm->sstable_count; i > 0; i--) {
        err = smt_lookup(&pm->sstables[i - 1], key, value);
        if (err == SMT_SUCCESS) {
            return DB_SUCCESS;
        }
    }

    return DB_ERROR_KEY_NOT_FOUND;
}

db_error_t persistence_batch_insert(PersistenceManager* pm, const char** keys, const char** values, size_t count) {
    if (!pm || !keys || !values) {
        return DB_ERROR_NULL_POINTER;
    }

    for (size_t i = 0; i < count; i++) {
        db_error_t err = persistence_insert(pm, keys[i], values[i]);
        if (err != DB_SUCCESS) {
            return err;
        }
    }

    return DB_SUCCESS;
}

db_error_t persistence_find_all(PersistenceManager* pm, char*** keys, char*** values, size_t* count) {
    if (!pm || !keys || !values || !count) {
        return DB_ERROR_NULL_POINTER;
    }

    *keys = NULL;
    *values = NULL;
    *count = 0;

    // First pass: count all elements
    size_t total_elements = 0;
    
    // Count in memtable
    for (int i = 0; i < pm->memtable.layer_count; i++) {
        total_elements += pm->memtable.layers[i].element_count;
    }

    // Count in SSTables
    for (size_t i = 0; i < pm->sstable_count; i++) {
        for (int j = 0; j < pm->sstables[i].layer_count; j++) {
            total_elements += pm->sstables[i].layers[j].element_count;
        }
    }

    if (total_elements == 0) {
        return DB_SUCCESS;
    }

    // Allocate memory
    *keys = malloc(total_elements * sizeof(char*));
    *values = malloc(total_elements * sizeof(char*));
    if (!*keys || !*values) {
        free(*keys);
        free(*values);
        *keys = NULL;
        *values = NULL;
        return DB_ERROR_MEMORY_ALLOCATION;
    }

    // Second pass: collect elements
    size_t idx = 0;

    // Collect from memtable
    for (int i = 0; i < pm->memtable.layer_count; i++) {
        Layer* layer = &pm->memtable.layers[i];
        for (int j = 0; j < layer->element_count; j++) {
            if (idx >= total_elements) break;
            
            (*keys)[idx] = strdup(layer->elements[j].key);
            (*values)[idx] = layer->elements[j].value ? strdup(layer->elements[j].value) : NULL;
            idx++;
        }
    }

    // Collect from SSTables (newest to oldest)
    for (size_t i = pm->sstable_count; i > 0; i--) {
        SMT* sstable = &pm->sstables[i - 1];
        for (int j = 0; j < sstable->layer_count; j++) {
            Layer* layer = &sstable->layers[j];
            for (int k = 0; k < layer->element_count; k++) {
                if (idx >= total_elements) break;
                
                // Skip duplicates (since we're going newest to oldest)
                int duplicate = 0;
                for (size_t l = 0; l < idx; l++) {
                    if (strcmp((*keys)[l], layer->elements[k].key) == 0) {
                        duplicate = 1;
                        break;
                    }
                }
                
                if (!duplicate) {
                    (*keys)[idx] = strdup(layer->elements[k].key);
                    (*values)[idx] = layer->elements[k].value ? strdup(layer->elements[k].value) : NULL;
                    idx++;
                }
            }
        }
    }

    *count = idx;
    return DB_SUCCESS;
}

db_error_t persistence_flush(PersistenceManager* pm) {
    if (!pm) {
        return DB_ERROR_NULL_POINTER;
    }

    // Skip if memtable is empty
    if (pm->memtable.total_elements == 0) {
        return DB_SUCCESS;
    }

    // Create SSTable file
    char sstable_path[2048];
    snprintf(sstable_path, sizeof(sstable_path), "%s/sstable_%zu.dat", pm->collection_path, pm->sstable_count);
    
    FILE* fp = fopen(sstable_path, "wb");
    if (!fp) {
        return DB_ERROR_IO_ERROR;
    }

    // Serialize memtable to SSTable
    smt_error_t err = smt_serialize(&pm->memtable, fp);
    fclose(fp);
    
    if (err != SMT_SUCCESS) {
        unlink(sstable_path);
        return (db_error_t)err;
    }

    // Add to SSTables array
    if (pm->sstable_count >= pm->sstable_capacity) {
        size_t new_capacity = pm->sstable_capacity * 2;
        SMT* new_sstables = realloc(pm->sstables, new_capacity * sizeof(SMT));
        if (!new_sstables) {
            unlink(sstable_path);
            return DB_ERROR_MEMORY_ALLOCATION;
        }
        pm->sstables = new_sstables;
        pm->sstable_capacity = new_capacity;
    }

    // Initialize and deserialize the new SSTable (to verify it)
    smt_init(&pm->sstables[pm->sstable_count]);
    fp = fopen(sstable_path, "rb");
    if (!fp) {
        smt_cleanup(&pm->sstables[pm->sstable_count]);
        unlink(sstable_path);
        return DB_ERROR_IO_ERROR;
    }
    
    err = smt_deserialize(&pm->sstables[pm->sstable_count], fp);
    fclose(fp);
    
    if (err != SMT_SUCCESS) {
        smt_cleanup(&pm->sstables[pm->sstable_count]);
        unlink(sstable_path);
        return (db_error_t)err;
    }

    pm->sstable_count++;

    // Reset memtable
    smt_cleanup(&pm->memtable);
    smt_init(&pm->memtable);

    // Reset WAL
    if (pm->wal) {
        fclose(pm->wal);
        
        char wal_path[2048];
        snprintf(wal_path, sizeof(wal_path), "%s/%s.wal", pm->collection_path, pm->collection_name);
        unlink(wal_path);
        
        pm->wal = fopen(wal_path, "a");
        if (!pm->wal) {
            return DB_ERROR_IO_ERROR;
        }
    }

    return DB_SUCCESS;
}

db_error_t persistence_get_root(PersistenceManager* pm, unsigned char* root_hash) {
    if (!pm || !root_hash) {
        return DB_ERROR_NULL_POINTER;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return DB_ERROR_MEMORY_ALLOCATION;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return DB_ERROR_INVALID_STATE;
    }

    // Include memtable root
    unsigned char memtable_root[HASH_SIZE];
    if (smt_get_root(&pm->memtable, memtable_root) != SMT_SUCCESS) {
        EVP_MD_CTX_free(ctx);
        return DB_ERROR_SMT_FAILED;
    }
    EVP_DigestUpdate(ctx, memtable_root, HASH_SIZE);

    // Include all SSTable roots
    for (size_t i = 0; i < pm->sstable_count; i++) {
        unsigned char sstable_root[HASH_SIZE];
        if (smt_get_root(&pm->sstables[i], sstable_root) != SMT_SUCCESS) {
            EVP_MD_CTX_free(ctx);
            return DB_ERROR_SMT_FAILED;
        }
        EVP_DigestUpdate(ctx, sstable_root, HASH_SIZE);
    }

    // Finalize the hash
    unsigned int hash_len;
    EVP_DigestFinal_ex(ctx, root_hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    return DB_SUCCESS;
}

db_error_t persistence_generate_proof(PersistenceManager* pm, const char* key, MembershipProof* proof) {
    if (!pm || !key || !proof) {
        return DB_ERROR_NULL_POINTER;
    }

    memset(proof, 0, sizeof(MembershipProof));

    // First check memtable
    smt_error_t err = smt_generate_proof(&pm->memtable, key, proof);
    if (err == SMT_SUCCESS) {
        return DB_SUCCESS;
    }

    // Then check SSTables (newest to oldest)
    for (size_t i = pm->sstable_count; i > 0; i--) {
        err = smt_generate_proof(&pm->sstables[i - 1], key, proof);
        if (err == SMT_SUCCESS) {
            return DB_SUCCESS;
        }
    }

    return DB_ERROR_KEY_NOT_FOUND;
}

db_error_t persistence_verify_proof(PersistenceManager* pm, const char* key, const char* value, 
                                   const MembershipProof* proof, int* valid) {
    if (!pm || !key || !proof || !valid) {
        return DB_ERROR_NULL_POINTER;
    }

    *valid = 0;

    // First try memtable
    smt_error_t err = smt_verify_proof(&pm->memtable, key, value, proof, valid);
    if (err == SMT_SUCCESS && *valid) {
        return DB_SUCCESS;
    }

    // Then try SSTables
    for (size_t i = 0; i < pm->sstable_count; i++) {
        err = smt_verify_proof(&pm->sstables[i], key, value, proof, valid);
        if (err == SMT_SUCCESS && *valid) {
            return DB_SUCCESS;
        }
    }

    return DB_ERROR_KEY_NOT_FOUND;
}

void persistence_cleanup(PersistenceManager* pm) {
    if (!pm) {
        return;
    }

    // Cleanup memtable
    smt_cleanup(&pm->memtable);

    // Cleanup SSTables
    for (size_t i = 0; i < pm->sstable_count; i++) {
        smt_cleanup(&pm->sstables[i]);
    }
    free(pm->sstables);

    // Close WAL
    if (pm->wal) {
        fclose(pm->wal);
    }

    // Free paths
    free(pm->collection_path);
    free(pm->collection_name);

    // Zero out the structure
    memset(pm, 0, sizeof(PersistenceManager));
}