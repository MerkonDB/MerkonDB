#include "smt_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <jansson.h>

#define MAX_DATABASES 10

DatabaseManager g_db_manager = {0};

static Database* find_database(const char* db_name) {
    if (!db_name || !g_db_manager.is_initialized) return NULL;
    pthread_mutex_lock(&g_db_manager.lock);
    for (size_t i = 0; i < g_db_manager.db_count; i++) {
        if (strcmp(g_db_manager.databases[i].name, db_name) == 0 && 
            g_db_manager.databases[i].is_open) {
            pthread_mutex_unlock(&g_db_manager.lock);
            return &g_db_manager.databases[i];
        }
    }
    pthread_mutex_unlock(&g_db_manager.lock);
    return NULL;
}

static Collection* find_collection(Database* db, const char* collection_name) {
    if (!db || !collection_name) return NULL;
    pthread_rwlock_rdlock(&db->lock);
    for (size_t i = 0; i < db->collection_count; i++) {
        if (strcmp(db->collections[i].name, collection_name) == 0 && 
            db->collections[i].is_open) {
            pthread_rwlock_unlock(&db->lock);
            return &db->collections[i];
        }
    }
    pthread_rwlock_unlock(&db->lock);
    return NULL;
}

static db_error_t ensure_persistence_dir() {
    if (g_db_manager.persistence_path[0] == '\0') return DB_SUCCESS;
    struct stat st = {0};
    if (stat(g_db_manager.persistence_path, &st) == -1) {
        if (mkdir(g_db_manager.persistence_path, 0700) == -1) return DB_ERROR_IO_ERROR;
    }
    return DB_SUCCESS;
}

static db_error_t update_indexes_for_record(Collection* col, const char* key, const char* value) {
    if (!col || !key || !value) {
        fprintf(stderr, "[ERROR] update_indexes_for_record: Null pointer input\n");
        return DB_ERROR_NULL_POINTER;
    }
    
    fprintf(stdout, "[DEBUG] update_indexes_for_record: Processing key '%s'\n", key);
    json_error_t error;
    json_t* root = json_loads(value, 0, &error);
    if (!root) {
        fprintf(stderr, "[ERROR] update_indexes_for_record: Invalid JSON for key %s: %s\n", key, error.text);
        return DB_ERROR_INVALID_JSON;
    }

    db_error_t result = DB_SUCCESS;
    
    for (size_t i = 0; i < col->indexed_field_count; i++) {
        if (!col->indexed_fields[i]) {
            fprintf(stderr, "[ERROR] update_indexes_for_record: Null indexed field at index %zu\n", i);
            result = DB_ERROR_INVALID_STATE;
            continue;
        }
        const char* field_name = col->indexed_fields[i];
        fprintf(stdout, "[DEBUG] update_indexes_for_record: Indexing field '%s'\n", field_name);
        json_t* field_value = json_object_get(root, field_name);
        
        if (field_value && (json_is_string(field_value) || json_is_integer(field_value) || json_is_real(field_value))) {
            const char* val_str = NULL;
            char val_buffer[64] = {0};
            
            if (json_is_string(field_value)) {
                val_str = json_string_value(field_value);
            } else if (json_is_integer(field_value)) {
                snprintf(val_buffer, sizeof(val_buffer), "%lld", (long long)json_integer_value(field_value));
                val_str = val_buffer;
            } else if (json_is_real(field_value)) {
                snprintf(val_buffer, sizeof(val_buffer), "%f", json_real_value(field_value));
                val_str = val_buffer;
            }
            
            if (val_str) {
                char index_key[256];
                snprintf(index_key, sizeof(index_key), "__index__:%s:%s", field_name, val_str);
                fprintf(stdout, "[DEBUG] update_indexes_for_record: Index key '%s'\n", index_key);

                char* current_list_str = NULL;
                smt_error_t lookup_err = smt_lookup(&col->tree, index_key, &current_list_str);
                fprintf(stdout, "[DEBUG] update_indexes_for_record: smt_lookup result for '%s': %d\n", index_key, lookup_err);
                
                json_t* list = NULL;
                if (lookup_err == SMT_SUCCESS && current_list_str) {
                    list = json_loads(current_list_str, 0, NULL);
                    if (!list) {
                        fprintf(stderr, "[ERROR] update_indexes_for_record: Failed to parse index list for '%s'\n", index_key);
                        result = DB_ERROR_INVALID_JSON;
                    }
                    free(current_list_str);
                }
                
                if (!list) {
                    list = json_array();
                    if (!list) {
                        fprintf(stderr, "[ERROR] update_indexes_for_record: Failed to create JSON array for '%s'\n", index_key);
                        result = DB_ERROR_MEMORY_ALLOCATION;
                        continue;
                    }
                    fprintf(stdout, "[DEBUG] update_indexes_for_record: Created new JSON array for '%s'\n", index_key);
                }

                int found = 0;
                size_t idx;
                json_t* item;
                json_array_foreach(list, idx, item) {
                    if (json_is_string(item) && strcmp(json_string_value(item), key) == 0) {
                        found = 1;
                        break;
                    }
                }
                
                if (!found) {
                    json_t* new_item = json_string(key);
                    if (!new_item) {
                        fprintf(stderr, "[ERROR] update_indexes_for_record: Failed to create JSON string for key '%s'\n", key);
                        result = DB_ERROR_MEMORY_ALLOCATION;
                        json_decref(list);
                        continue;
                    }
                    json_array_append_new(list, new_item);
                    fprintf(stdout, "[DEBUG] update_indexes_for_record: Appended key '%s' to index list\n", key);
                }

                char* new_list_str = json_dumps(list, JSON_COMPACT);
                if (new_list_str) {
                    fprintf(stdout, "[DEBUG] update_indexes_for_record: Inserting index '%s' into SMT\n", index_key);
                    smt_error_t insert_err = smt_insert(&col->tree, index_key, new_list_str);
                    if (insert_err != SMT_SUCCESS) {
                        fprintf(stderr, "[ERROR] update_indexes_for_record: smt_insert failed for '%s' with error %d\n", index_key, insert_err);
                        result = DB_ERROR_SMT_FAILED;
                    }
                    free(new_list_str);
                } else {
                    fprintf(stderr, "[ERROR] update_indexes_for_record: Failed to serialize index list for '%s'\n", index_key);
                    result = DB_ERROR_MEMORY_ALLOCATION;
                }
                
                json_decref(list);
            }
        }
    }
    
    json_decref(root);
    fprintf(stdout, "[DEBUG] update_indexes_for_record: Completed for key '%s'\n", key);
    return result;
}
static db_error_t remove_from_indexes(Collection* col, const char* key, const char* value) {
    json_t* root = json_loads(value, 0, NULL);
    if (!root) return DB_ERROR_INVALID_JSON;

    for (size_t i = 0; i < col->indexed_field_count; i++) {
        const char* field_name = col->indexed_fields[i];
        json_t* field_value = json_object_get(root, field_name);
        if (field_value && json_is_string(field_value)) {
            const char* val_str = json_string_value(field_value);
            char index_key[256];
            snprintf(index_key, sizeof(index_key), "__index__:%s:%s", field_name, val_str);

            char* current_list_str;
            smt_error_t lookup_err = smt_lookup(&col->tree, index_key, &current_list_str);
            if (lookup_err == SMT_SUCCESS) {
                json_t* list = json_loads(current_list_str, 0, NULL);
                free(current_list_str);
                if (list) {
                    size_t idx;
                    json_t* item;
                    json_array_foreach(list, idx, item) {
                        if (strcmp(json_string_value(item), key) == 0) {
                            json_array_remove(list, idx);
                            break;
                        }
                    }
                    if (json_array_size(list) == 0) {
                        smt_delete(&col->tree, index_key);
                    } else {
                        char* new_list_str = json_dumps(list, JSON_COMPACT);
                        if (new_list_str) {
                            smt_insert(&col->tree, index_key, new_list_str);
                            free(new_list_str);
                        }
                    }
                    json_decref(list);
                }
            }
        }
    }
    json_decref(root);
    return DB_SUCCESS;
}

static db_error_t build_index_for_field(Database* db, Collection* col, const char* field_name) {
    char** keys = NULL;
    char** values = NULL;
    size_t count = 0;
    db_error_t err = db_find_all(db->name, col->name, &keys, &values, &count);
    if (err != DB_SUCCESS) {
        return err;
    }

    db_error_t final_err = DB_SUCCESS;
    
    for (size_t i = 0; i < count; i++) {
        if (!strstr(keys[i], "__index__:")) {  // Skip index entries
            json_error_t json_error;
            json_t* root = json_loads(values[i], 0, &json_error);
            if (!root) {
                fprintf(stderr, "[ERROR] build_index_for_field: Failed to parse JSON for key %s: %s\n", 
                        keys[i], json_error.text);
                continue;  // Skip invalid JSON but continue processing other records
            }

            json_t* field_value = json_object_get(root, field_name);
            if (field_value && (json_is_string(field_value) || json_is_integer(field_value) || json_is_real(field_value))) {
                const char* val_str = NULL;
                char val_buffer[64];
                
                if (json_is_string(field_value)) {
                    val_str = json_string_value(field_value);
                } else if (json_is_integer(field_value)) {
                    snprintf(val_buffer, sizeof(val_buffer), "%lld", (long long)json_integer_value(field_value));
                    val_str = val_buffer;
                } else if (json_is_real(field_value)) {
                    snprintf(val_buffer, sizeof(val_buffer), "%f", json_real_value(field_value));
                    val_str = val_buffer;
                }
                
                if (val_str) {
                    char index_key[256];
                    snprintf(index_key, sizeof(index_key), "__index__:%s:%s", field_name, val_str);

                    char* current_list_str = NULL;
                    smt_error_t lookup_err = smt_lookup(&col->tree, index_key, &current_list_str);
                    
                    json_t* list = NULL;
                    if (lookup_err == SMT_SUCCESS && current_list_str) {
                        list = json_loads(current_list_str, 0, NULL);
                        free(current_list_str);
                    }
                    
                    if (!list) {
                        list = json_array();
                        if (!list) {
                            json_decref(root);
                            final_err = DB_ERROR_MEMORY_ALLOCATION;
                            break;
                        }
                    }

                    // Check if key already exists in the list
                    int found = 0;
                    size_t idx;
                    json_t* item;
                    json_array_foreach(list, idx, item) {
                        if (json_is_string(item) && strcmp(json_string_value(item), keys[i]) == 0) {
                            found = 1;
                            break;
                        }
                    }
                    
                    if (!found) {
                        json_t* new_item = json_string(keys[i]);
                        if (!new_item) {
                            json_decref(list);
                            json_decref(root);
                            final_err = DB_ERROR_MEMORY_ALLOCATION;
                            break;
                        }
                        json_array_append_new(list, new_item);
                    }

                    char* new_list_str = json_dumps(list, JSON_COMPACT);
                    if (new_list_str) {
                        smt_insert(&col->tree, index_key, new_list_str);
                        free(new_list_str);
                    } else {
                        final_err = DB_ERROR_MEMORY_ALLOCATION;
                    }
                    
                    json_decref(list);
                }
            }
            json_decref(root);
        }
    }

    db_free_list(keys, count);
    db_free_list(values, count);
    return final_err;
}

static db_error_t serialize_database(Database* db, int fd) {
    json_t* root = json_object();
    if (!root) return DB_ERROR_MEMORY_ALLOCATION;

    json_object_set_new(root, "name", json_string(db->name));
    json_object_set_new(root, "created_at", json_integer(db->stats.created_at));
    json_object_set_new(root, "last_modified", json_integer(db->stats.last_modified));

    json_t* collections = json_array();
    for (size_t i = 0; i < db->collection_count; i++) {
        Collection* col = &db->collections[i];
        if (!col->is_open) continue;

        json_t* collection_obj = json_object();
        json_object_set_new(collection_obj, "name", json_string(col->name));
        json_object_set_new(collection_obj, "created_at", json_integer(col->created_at));
        json_object_set_new(collection_obj, "last_modified", json_integer(col->last_modified));

        json_t* records = json_array();
        json_t* indexes = json_array();
        for (int layer_idx = 0; layer_idx < col->tree.layer_count; layer_idx++) {
            Layer* layer = &col->tree.layers[layer_idx];
            for (int elem_idx = 0; elem_idx < layer->element_count; elem_idx++) {
                Element* elem = &layer->elements[elem_idx];
                json_t* record = json_object();
                json_object_set_new(record, "key", json_string(elem->key));
                json_object_set_new(record, "value", elem->value ? json_string(elem->value) : json_null());
                if (strstr(elem->key, "__index__:")) {
                    json_array_append_new(indexes, record);
                } else {
                    json_array_append_new(records, record);
                }
            }
        }
        json_object_set_new(collection_obj, "records", records);
        json_object_set_new(collection_obj, "indexes", indexes);

        json_t* indexed_fields = json_array();
        for (size_t j = 0; j < col->indexed_field_count; j++) {
            json_array_append_new(indexed_fields, json_string(col->indexed_fields[j]));
        }
        json_object_set_new(collection_obj, "indexed_fields", indexed_fields);

        json_array_append_new(collections, collection_obj);
    }
    json_object_set_new(root, "collections", collections);

    char* json_str = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    if (!json_str) return DB_ERROR_MEMORY_ALLOCATION;

    ssize_t written = write(fd, json_str, strlen(json_str));
    free(json_str);
    if (written == -1) return DB_ERROR_IO_ERROR;

    return DB_SUCCESS;
}

db_error_t db_list_indexes(const char* db_name, const char* collection_name, char*** indexed_fields, size_t* count) {
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;
    
    Collection* col = find_collection(db, collection_name);
    if (!col) return DB_ERROR_COLLECTION_NOT_FOUND;
    
    pthread_rwlock_rdlock(&col->lock);
    
    *indexed_fields = malloc(col->indexed_field_count * sizeof(char*));
    if (!*indexed_fields) {
        pthread_rwlock_unlock(&col->lock);
        return DB_ERROR_MEMORY_ALLOCATION;
    }
    
    for (size_t i = 0; i < col->indexed_field_count; i++) {
        (*indexed_fields)[i] = strdup(col->indexed_fields[i]);
        if (!(*indexed_fields)[i]) {
            for (size_t j = 0; j < i; j++) {
                free((*indexed_fields)[j]);
            }
            free(*indexed_fields);
            pthread_rwlock_unlock(&col->lock);
            return DB_ERROR_MEMORY_ALLOCATION;
        }
    }
    
    *count = col->indexed_field_count;
    pthread_rwlock_unlock(&col->lock);
    return DB_SUCCESS;
}

db_error_t db_drop_index(const char* db_name, const char* collection_name, const char* field_name) {
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;
    
    Collection* col = find_collection(db, collection_name);
    if (!col) return DB_ERROR_COLLECTION_NOT_FOUND;
    
    pthread_rwlock_wrlock(&col->lock);
    
    int found = 0;
    for (size_t i = 0; i < col->indexed_field_count; i++) {
        if (strcmp(col->indexed_fields[i], field_name) == 0) {
            found = 1;
            free(col->indexed_fields[i]);
            for (size_t j = i; j < col->indexed_field_count - 1; j++) {
                col->indexed_fields[j] = col->indexed_fields[j+1];
            }
            col->indexed_field_count--;
            break;
        }
    }
    
    if (!found) {
        pthread_rwlock_unlock(&col->lock);
        return DB_ERROR_INDEX_NOT_FOUND;
    }
    
    char** keys_to_delete = NULL;
    size_t key_count = 0;
    char prefix[256];
    snprintf(prefix, sizeof(prefix), "__index__:%s:", field_name);
    
    for (int layer_idx = 0; layer_idx < col->tree.layer_count; layer_idx++) {
        Layer* layer = &col->tree.layers[layer_idx];
        for (int elem_idx = 0; elem_idx < layer->element_count; elem_idx++) {
            Element* elem = &layer->elements[elem_idx];
            if (strncmp(elem->key, prefix, strlen(prefix)) == 0) {
                keys_to_delete = realloc(keys_to_delete, (key_count + 1) * sizeof(char*));
                if (!keys_to_delete) {
                    pthread_rwlock_unlock(&col->lock);
                    return DB_ERROR_MEMORY_ALLOCATION;
                }
                keys_to_delete[key_count] = strdup(elem->key);
                if (!keys_to_delete[key_count]) {
                    for (size_t k = 0; k < key_count; k++) {
                        free(keys_to_delete[k]);
                    }
                    free(keys_to_delete);
                    pthread_rwlock_unlock(&col->lock);
                    return DB_ERROR_MEMORY_ALLOCATION;
                }
                key_count++;
            }
        }
    }
    
    for (size_t i = 0; i < key_count; i++) {
        smt_delete(&col->tree, keys_to_delete[i]);
        free(keys_to_delete[i]);
    }
    free(keys_to_delete);
    
    pthread_rwlock_unlock(&col->lock);
    return DB_SUCCESS;
}

static db_error_t deserialize_database(Database* db, int fd) {
    struct stat st;
    if (fstat(fd, &st) == -1) return DB_ERROR_IO_ERROR;

    char* buffer = malloc(st.st_size + 1);
    if (!buffer) return DB_ERROR_MEMORY_ALLOCATION;

    if (read(fd, buffer, st.st_size) != st.st_size) {
        free(buffer);
        return DB_ERROR_IO_ERROR;
    }
    buffer[st.st_size] = '\0';

    json_error_t error;
    json_t* root = json_loads(buffer, 0, &error);
    free(buffer);
    if (!root) return DB_ERROR_CORRUPTED_DATA;

    json_t* name = json_object_get(root, "name");
    if (name) strncpy(db->name, json_string_value(name), MAX_DB_NAME_LEN - 1);

    json_t* created_at = json_object_get(root, "created_at");
    if (created_at) db->stats.created_at = json_integer_value(created_at);

    json_t* last_modified = json_object_get(root, "last_modified");
    if (last_modified) db->stats.last_modified = json_integer_value(last_modified);

    json_t* collections = json_object_get(root, "collections");
    if (collections && json_is_array(collections)) {
        size_t index;
        json_t* value;
        json_array_foreach(collections, index, value) {
            json_t* col_name = json_object_get(value, "name");
            if (!col_name) continue;

            const char* name_str = json_string_value(col_name);
            db_error_t err = db_create_collection(db->name, name_str);
            if (err != DB_SUCCESS) continue;

            Collection* col = find_collection(db, name_str);
            if (!col) continue;

            json_t* records = json_object_get(value, "records");
            json_t* indexes = json_object_get(value, "indexes");
            if (records && json_is_array(records)) {
                size_t rec_idx;
                json_t* rec_val;
                json_array_foreach(records, rec_idx, rec_val) {
                    json_t* key = json_object_get(rec_val, "key");
                    json_t* val = json_object_get(rec_val, "value");
                    if (key) {
                        const char* key_str = json_string_value(key);
                        const char* val_str = json_is_string(val) ? json_string_value(val) : NULL;
                        pthread_rwlock_wrlock(&col->lock);
                        smt_insert(&col->tree, key_str, val_str);
                        pthread_rwlock_unlock(&col->lock);
                    }
                }
            }
            if (indexes && json_is_array(indexes)) {
                size_t idx_idx;
                json_t* idx_val;
                json_array_foreach(indexes, idx_idx, idx_val) {
                    json_t* key = json_object_get(idx_val, "key");
                    json_t* val = json_object_get(idx_val, "value");
                    if (key) {
                        const char* key_str = json_string_value(key);
                        const char* val_str = json_is_string(val) ? json_string_value(val) : NULL;
                        pthread_rwlock_wrlock(&col->lock);
                        smt_insert(&col->tree, key_str, val_str);
                        pthread_rwlock_unlock(&col->lock);
                    }
                }
            }

            json_t* indexed_fields = json_object_get(value, "indexed_fields");
            if (indexed_fields && json_is_array(indexed_fields)) {
                size_t field_count = json_array_size(indexed_fields);
                for (size_t i = 0; i < field_count && i < MAX_INDEX_FIELDS; i++) {
                    json_t* field = json_array_get(indexed_fields, i);
                    if (json_is_string(field)) {
                        col->indexed_fields[i] = strdup(json_string_value(field));
                        col->indexed_field_count++;
                    }
                }
            }
        }
    }
    json_decref(root);
    return DB_SUCCESS;
}

db_error_t db_manager_init(const char* persistence_path) {
    return db_manager_init_with_config(DEFAULT_MAX_DATABASES, DEFAULT_MAX_COLLECTIONS, persistence_path);
}

db_error_t db_manager_init_with_config(size_t max_databases, size_t max_collections, const char* persistence_path) {
    if (g_db_manager.is_initialized) return DB_SUCCESS;

    memset(&g_db_manager, 0, sizeof(DatabaseManager));
    if (pthread_mutex_init(&g_db_manager.lock, NULL) != 0) return DB_ERROR_MEMORY_ALLOCATION;

    g_db_manager.databases = calloc(max_databases, sizeof(Database));
    if (!g_db_manager.databases) {
        pthread_mutex_destroy(&g_db_manager.lock);
        return DB_ERROR_MEMORY_ALLOCATION;
    }

    g_db_manager.db_capacity = max_databases;
    g_db_manager.db_count = 0;

    if (persistence_path) {
        strncpy(g_db_manager.persistence_path, persistence_path, sizeof(g_db_manager.persistence_path) - 1);
        db_error_t err = ensure_persistence_dir();
        if (err != DB_SUCCESS) {
            free(g_db_manager.databases);
            pthread_mutex_destroy(&g_db_manager.lock);
            return err;
        }
    }

    g_db_manager.is_initialized = 1;
    return DB_SUCCESS;
}

void db_manager_cleanup() {
    if (!g_db_manager.is_initialized) return;

    pthread_mutex_lock(&g_db_manager.lock);

    for (size_t i = 0; i < g_db_manager.db_count; i++) {
        Database* db = &g_db_manager.databases[i];
        if (db->is_open) {
            pthread_rwlock_wrlock(&db->lock);
            for (size_t j = 0; j < db->collection_count; j++) {
                Collection* col = &db->collections[j];
                if (col->is_open) {
                    pthread_rwlock_wrlock(&col->lock);
                    smt_cleanup(&col->tree);
                    for (size_t k = 0; k < col->indexed_field_count; k++) {
                        free(col->indexed_fields[k]);
                    }
                    pthread_rwlock_unlock(&col->lock);
                    pthread_rwlock_destroy(&col->lock);
                }
            }
            free(db->collections);
            pthread_rwlock_unlock(&db->lock);
            pthread_rwlock_destroy(&db->lock);
        }
    }

    free(g_db_manager.databases);
    pthread_mutex_unlock(&g_db_manager.lock);
    pthread_mutex_destroy(&g_db_manager.lock);

    memset(&g_db_manager, 0, sizeof(DatabaseManager));
}

db_error_t db_create(const char* db_name) {
    if (!db_name) return DB_ERROR_NULL_POINTER;
    if (strlen(db_name) >= MAX_DB_NAME_LEN) return DB_ERROR_INVALID_PARAMETER;

    pthread_mutex_lock(&g_db_manager.lock);

    for (size_t i = 0; i < g_db_manager.db_count; i++) {
        if (strcmp(g_db_manager.databases[i].name, db_name) == 0) {
            pthread_mutex_unlock(&g_db_manager.lock);
            return g_db_manager.databases[i].is_open ? DB_ERROR_DATABASE_EXISTS : DB_SUCCESS;
        }
    }

    if (g_db_manager.db_count >= g_db_manager.db_capacity) {
        pthread_mutex_unlock(&g_db_manager.lock);
        return DB_ERROR_MAX_LIMIT_REACHED;
    }

    Database* db = &g_db_manager.databases[g_db_manager.db_count++];
    memset(db, 0, sizeof(Database));

    strncpy(db->name, db_name, MAX_DB_NAME_LEN - 1);
    db->collection_capacity = DEFAULT_MAX_COLLECTIONS;
    db->collections = calloc(db->collection_capacity, sizeof(Collection));
    if (!db->collections) {
        g_db_manager.db_count--;
        pthread_mutex_unlock(&g_db_manager.lock);
        return DB_ERROR_MEMORY_ALLOCATION;
    }

    if (pthread_rwlock_init(&db->lock, NULL) != 0) {
        free(db->collections);
        g_db_manager.db_count--;
        pthread_mutex_unlock(&g_db_manager.lock);
        return DB_ERROR_MEMORY_ALLOCATION;
    }

    db->stats.created_at = time(NULL);
    db->stats.last_modified = db->stats.created_at;
    db->is_open = 1;

    pthread_mutex_unlock(&g_db_manager.lock);
    return DB_SUCCESS;
}

db_error_t db_open(const char* db_name) {
    if (!db_name) return DB_ERROR_NULL_POINTER;

    pthread_mutex_lock(&g_db_manager.lock);

    for (size_t i = 0; i < g_db_manager.db_count; i++) {
        if (strcmp(g_db_manager.databases[i].name, db_name) == 0) {
            if (g_db_manager.databases[i].is_open) {
                pthread_mutex_unlock(&g_db_manager.lock);
                return DB_SUCCESS;
            }
            g_db_manager.databases[i].is_open = 1;
            pthread_mutex_unlock(&g_db_manager.lock);
            return DB_SUCCESS;
        }
    }

    pthread_mutex_unlock(&g_db_manager.lock);
    return DB_ERROR_DATABASE_NOT_FOUND;
}

db_error_t db_close(const char* db_name) {
    if (!db_name) return DB_ERROR_NULL_POINTER;

    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;

    pthread_rwlock_wrlock(&db->lock);
    db->is_open = 0;
    pthread_rwlock_unlock(&db->lock);

    return DB_SUCCESS;
}

db_error_t db_drop(const char* db_name) {
    if (!db_name) return DB_ERROR_NULL_POINTER;

    pthread_mutex_lock(&g_db_manager.lock);

    for (size_t i = 0; i < g_db_manager.db_count; i++) {
        if (strcmp(g_db_manager.databases[i].name, db_name) == 0) {
            Database* db = &g_db_manager.databases[i];
            pthread_rwlock_wrlock(&db->lock);

            for (size_t j = 0; j < db->collection_count; j++) {
                Collection* col = &db->collections[j];
                if (col->is_open) {
                    pthread_rwlock_wrlock(&col->lock);
                    smt_cleanup(&col->tree);
                    for (size_t k = 0; k < col->indexed_field_count; k++) {
                        free(col->indexed_fields[k]);
                    }
                    pthread_rwlock_unlock(&col->lock);
                    pthread_rwlock_destroy(&col->lock);
                }
            }

            free(db->collections);
            pthread_rwlock_unlock(&db->lock);
            pthread_rwlock_destroy(&db->lock);

            for (size_t j = i; j < g_db_manager.db_count - 1; j++) {
                g_db_manager.databases[j] = g_db_manager.databases[j+1];
            }

            g_db_manager.db_count--;
            pthread_mutex_unlock(&g_db_manager.lock);
            return DB_SUCCESS;
        }
    }

    pthread_mutex_unlock(&g_db_manager.lock);
    return DB_ERROR_DATABASE_NOT_FOUND;
}

db_error_t db_exists(const char* db_name, int* exists) {
    if (!db_name || !exists) return DB_ERROR_NULL_POINTER;

    *exists = 0;
    pthread_mutex_lock(&g_db_manager.lock);

    for (size_t i = 0; i < g_db_manager.db_count; i++) {
        if (strcmp(g_db_manager.databases[i].name, db_name) == 0) {
            *exists = 1;
            break;
        }
    }

    pthread_mutex_unlock(&g_db_manager.lock);
    return DB_SUCCESS;
}

db_error_t db_list(char*** db_names, size_t* count) {
    if (!db_names || !count) return DB_ERROR_NULL_POINTER;

    *db_names = NULL;
    *count = 0;

    pthread_mutex_lock(&g_db_manager.lock);

    if (g_db_manager.db_count == 0) {
        pthread_mutex_unlock(&g_db_manager.lock);
        return DB_SUCCESS;
    }

    *db_names = malloc(g_db_manager.db_count * sizeof(char*));
    if (!*db_names) {
        pthread_mutex_unlock(&g_db_manager.lock);
        return DB_ERROR_MEMORY_ALLOCATION;
    }

    for (size_t i = 0; i < g_db_manager.db_count; i++) {
        (*db_names)[i] = strdup(g_db_manager.databases[i].name);
        if (!(*db_names)[i]) {
            for (size_t j = 0; j < i; j++) {
                free((*db_names)[j]);
            }
            free(*db_names);
            *db_names = NULL;
            pthread_mutex_unlock(&g_db_manager.lock);
            return DB_ERROR_MEMORY_ALLOCATION;
        }
    }

    *count = g_db_manager.db_count;
    pthread_mutex_unlock(&g_db_manager.lock);
    return DB_SUCCESS;
}

db_error_t db_get_stats(const char* db_name, DatabaseStats* stats) {
    if (!db_name || !stats) return DB_ERROR_NULL_POINTER;

    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;

    pthread_rwlock_rdlock(&db->lock);

    *stats = db->stats;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1) {
        for (size_t i = 0; i < db->collection_count; i++) {
            Collection* col = &db->collections[i];
            if (!col->is_open) continue;

            pthread_rwlock_rdlock(&col->lock);
            unsigned char col_root[HASH_SIZE];
            if (smt_get_root(&col->tree, col_root) == SMT_SUCCESS) {
                EVP_DigestUpdate(ctx, col_root, HASH_SIZE);
                EVP_DigestUpdate(ctx, col->name, strlen(col->name));
            }
            pthread_rwlock_unlock(&col->lock);
        }

        unsigned int hash_len;
        EVP_DigestFinal_ex(ctx, stats->root_hash, &hash_len);
    } else {
        memset(stats->root_hash, 0, HASH_SIZE);
    }

    if (ctx) EVP_MD_CTX_free(ctx);
    pthread_rwlock_unlock(&db->lock);

    return DB_SUCCESS;
}

db_error_t db_create_collection(const char* db_name, const char* collection_name) {
    if (!db_name || !collection_name) return DB_ERROR_NULL_POINTER;
    if (strlen(collection_name) >= MAX_COLLECTION_NAME_LEN) return DB_ERROR_INVALID_PARAMETER;

    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;

    pthread_rwlock_wrlock(&db->lock);

    for (size_t i = 0; i < db->collection_count; i++) {
        if (strcmp(db->collections[i].name, collection_name) == 0) {
            pthread_rwlock_unlock(&db->lock);
            return db->collections[i].is_open ? DB_ERROR_COLLECTION_EXISTS : DB_SUCCESS;
        }
    }

    if (db->collection_count >= db->collection_capacity) {
        size_t new_capacity = db->collection_capacity * 2;
        Collection* new_collections = realloc(db->collections, new_capacity * sizeof(Collection));
        if (!new_collections) {
            pthread_rwlock_unlock(&db->lock);
            return DB_ERROR_MEMORY_ALLOCATION;
        }
        db->collections = new_collections;
        db->collection_capacity = new_capacity;
    }

    Collection* col = &db->collections[db->collection_count++];
    memset(col, 0, sizeof(Collection));

    strncpy(col->name, collection_name, MAX_COLLECTION_NAME_LEN - 1);
    col->created_at = time(NULL);
    col->last_modified = col->created_at;
    col->is_open = 1;

    if (pthread_rwlock_init(&col->lock, NULL) != 0) {
        db->collection_count--;
        pthread_rwlock_unlock(&db->lock);
        return DB_ERROR_MEMORY_ALLOCATION;
    }

    smt_error_t err = smt_init(&col->tree);
    if (err != SMT_SUCCESS) {
        pthread_rwlock_destroy(&col->lock);
        db->collection_count--;
        pthread_rwlock_unlock(&db->lock);
        return (db_error_t)err;
    }

    db->stats.total_collections++;
    db->stats.last_modified = time(NULL);

    pthread_rwlock_unlock(&db->lock);
    return DB_SUCCESS;
}

db_error_t db_drop_collection(const char* db_name, const char* collection_name) {
    if (!db_name || !collection_name) {
        fprintf(stderr, "[ERROR] db_drop_collection: Null pointer detected\n");
        return DB_ERROR_NULL_POINTER;
    }

    Database* db = find_database(db_name);
    if (!db) {
        fprintf(stderr, "[ERROR] db_drop_collection: Database '%s' not found\n", db_name);
        return DB_ERROR_DATABASE_NOT_FOUND;
    }

    pthread_rwlock_wrlock(&db->lock);
    for (size_t i = 0; i < db->collection_count; i++) {
        Collection* col = &db->collections[i];
        if (strcmp(col->name, collection_name) == 0) {
            if (!col->is_open) {
                pthread_rwlock_unlock(&db->lock);
                fprintf(stderr, "[ERROR] db_drop_collection: Collection '%s' is not open\n", collection_name);
                return DB_ERROR_COLLECTION_NOT_FOUND;
            }

            pthread_rwlock_wrlock(&col->lock);
            smt_cleanup(&col->tree);
            pthread_rwlock_destroy(&col->lock);

            // Clear indexed_fields
            for (size_t j = 0; j < col->indexed_field_count; j++) {
                free(col->indexed_fields[j]);
                col->indexed_fields[j] = NULL;
            }
            col->indexed_field_count = 0;

            // Shift remaining collections
            for (size_t j = i; j < db->collection_count - 1; j++) {
                db->collections[j] = db->collections[j + 1];
            }
            db->collection_count--;
            db->stats.total_collections--;
            db->stats.last_modified = time(NULL);
            pthread_rwlock_unlock(&db->lock);
            fprintf(stdout, "[DEBUG] db_drop_collection: Dropped collection '%s'\n", collection_name);
            return DB_SUCCESS;
        }
    }

    pthread_rwlock_unlock(&db->lock);
    fprintf(stderr, "[ERROR] db_drop_collection: Collection '%s' not found\n", collection_name);
    return DB_ERROR_COLLECTION_NOT_FOUND;
}

static db_error_t db_find_all_internal(Collection* col, char*** keys, char*** values, size_t* count) {
    if (!col || !keys || !values || !count) return DB_ERROR_NULL_POINTER;

    *keys = NULL;
    *values = NULL;
    *count = 0;

    size_t total_elements = col->record_count;

    if (total_elements == 0) {
        return DB_SUCCESS;
    }

    *keys = malloc(total_elements * sizeof(char*));
    *values = malloc(total_elements * sizeof(char*));
    if (!*keys || !*values) {
        free(*keys);
        free(*values);
        return DB_ERROR_MEMORY_ALLOCATION;
    }

    size_t idx = 0;
    for (int i = 0; i < col->tree.layer_count && idx < total_elements; i++) {
        Layer* layer = &col->tree.layers[i];
        for (int j = 0; j < layer->element_count && idx < total_elements; j++) {
            Element* elem = &layer->elements[j];
            if (!strstr(elem->key, "__index__:")) {  // Exclude index keys
                (*keys)[idx] = strdup(elem->key);
                (*values)[idx] = elem->value ? strdup(elem->value) : NULL;

                if (!(*keys)[idx] || (elem->value && !(*values)[idx])) {
                    for (size_t k = 0; k < idx; k++) {
                        free((*keys)[k]);
                        free((*values)[k]);
                    }
                    free(*keys);
                    free(*values);
                    return DB_ERROR_MEMORY_ALLOCATION;
                }
                idx++;
            }
        }
    }

    *count = idx;
    return DB_SUCCESS;
}


db_error_t db_list_collections(const char* db_name, char*** collection_names, size_t* count) {
    if (!db_name || !collection_names || !count) return DB_ERROR_NULL_POINTER;

    *collection_names = NULL;
    *count = 0;

    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;

    pthread_rwlock_rdlock(&db->lock);

    if (db->collection_count == 0) {
        pthread_rwlock_unlock(&db->lock);
        return DB_SUCCESS;
    }

    *collection_names = malloc(db->collection_count * sizeof(char*));
    if (!*collection_names) {
        pthread_rwlock_unlock(&db->lock);
        return DB_ERROR_MEMORY_ALLOCATION;
    }

    for (size_t i = 0; i < db->collection_count; i++) {
        (*collection_names)[i] = strdup(db->collections[i].name);
        if (!(*collection_names)[i]) {
            for (size_t j = 0; j < i; j++) {
                free((*collection_names)[j]);
            }
            free(*collection_names);
            *collection_names = NULL;
            pthread_rwlock_unlock(&db->lock);
            return DB_ERROR_MEMORY_ALLOCATION;
        }
    }

    *count = db->collection_count;
    pthread_rwlock_unlock(&db->lock);
    return DB_SUCCESS;
}

db_error_t db_collection_exists(const char* db_name, const char* collection_name, int* exists) {
    if (!db_name || !collection_name || !exists) return DB_ERROR_NULL_POINTER;

    *exists = 0;
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;

    pthread_rwlock_rdlock(&db->lock);

    for (size_t i = 0; i < db->collection_count; i++) {
        if (strcmp(db->collections[i].name, collection_name) == 0) {
            *exists = 1;
            break;
        }
    }

    pthread_rwlock_unlock(&db->lock);
    return DB_SUCCESS;
}

db_error_t db_insert(const char* db_name, const char* collection_name, const char* key, const char* value) {
    fprintf(stdout, "[DEBUG] db_insert: Starting for key '%s' in database '%s', collection '%s'\n", key, db_name, collection_name);
    if (!db_name || !collection_name || !key || !value) {
        fprintf(stderr, "[ERROR] db_insert: Null pointer input\n");
        return DB_ERROR_NULL_POINTER;
    }

    Database* db = find_database(db_name);
    if (!db) {
        fprintf(stderr, "[ERROR] db_insert: Database '%s' not found\n", db_name);
        return DB_ERROR_DATABASE_NOT_FOUND;
    }

    Collection* col = find_collection(db, collection_name);
    if (!col) {
        fprintf(stderr, "[ERROR] db_insert: Collection '%s' not found in database '%s'\n", collection_name, db_name);
        return DB_ERROR_COLLECTION_NOT_FOUND;
    }

    fprintf(stdout, "[DEBUG] db_insert: Acquiring write lock for collection '%s'\n", collection_name);
    pthread_rwlock_wrlock(&col->lock);

    char* existing_value = NULL;
    fprintf(stdout, "[DEBUG] db_insert: Performing smt_lookup for key '%s'\n", key);
    smt_error_t lookup_result = smt_lookup(&col->tree, key, &existing_value);

    fprintf(stdout, "[DEBUG] db_insert: Performing smt_insert for key '%s' with value '%s'\n", key, value);
    smt_error_t err = smt_insert(&col->tree, key, value);
    if (err != SMT_SUCCESS) {
        fprintf(stderr, "[ERROR] db_insert: smt_insert failed for key '%s' with error %d\n", key, err);
        if (existing_value) free(existing_value);
        pthread_rwlock_unlock(&col->lock);
        return (db_error_t)err;
    }

    fprintf(stdout, "[DEBUG] db_insert: smt_insert succeeded for key '%s'\n", key);
    if (value && col->indexed_field_count > 0) {
        fprintf(stdout, "[DEBUG] db_insert: Updating indexes for key '%s'\n", key);
        db_error_t index_result = update_indexes_for_record(col, key, value);
        if (index_result != DB_SUCCESS) {
            fprintf(stderr, "[ERROR] db_insert: Index update failed for key '%s' with error %d\n", key, index_result);
        }
    }

    if (lookup_result == SMT_ERROR_KEY_NOT_FOUND) {
        col->record_count++;
        db->stats.total_records++;
        fprintf(stdout, "[DEBUG] db_insert: Incremented record count for new key '%s'\n", key);
    } else if (value && existing_value && strcmp(value, existing_value) != 0) {
        db->stats.total_updates++;
        fprintf(stdout, "[DEBUG] db_insert: Incremented update count for key '%s'\n", key);
    }

    col->last_modified = time(NULL);
    db->stats.last_modified = col->last_modified;
    fprintf(stdout, "[DEBUG] db_insert: Updated last_modified for collection '%s'\n", collection_name);

    if (existing_value) free(existing_value);
    pthread_rwlock_unlock(&col->lock);
    fprintf(stdout, "[DEBUG] db_insert: Released write lock for collection '%s'\n", collection_name);

    fprintf(stdout, "[DEBUG] db_insert: Completed successfully for key '%s'\n", key);
    return DB_SUCCESS;
}

db_error_t db_find(const char* db_name, const char* collection_name, const char* key, char** value) {
    if (!db_name || !collection_name || !key || !value) return DB_ERROR_NULL_POINTER;

    *value = NULL;
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;

    Collection* col = find_collection(db, collection_name);
    if (!col) return DB_ERROR_COLLECTION_NOT_FOUND;

    pthread_rwlock_rdlock(&col->lock);
    smt_error_t err = smt_lookup(&col->tree, key, value);
    pthread_rwlock_unlock(&col->lock);

    return (db_error_t)err;
}

db_error_t db_update(const char* db_name, const char* collection_name, const char* key, const char* value) {
    if (!db_name || !collection_name || !key) return DB_ERROR_NULL_POINTER;

    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;

    Collection* col = find_collection(db, collection_name);
    if (!col) return DB_ERROR_COLLECTION_NOT_FOUND;

    pthread_rwlock_wrlock(&col->lock);

    char* old_value = NULL;
    smt_error_t lookup_err = smt_lookup(&col->tree, key, &old_value);

    smt_error_t err = smt_insert(&col->tree, key, value);
    if (err != SMT_SUCCESS) {
        if (old_value) free(old_value);
        pthread_rwlock_unlock(&col->lock);
        return (db_error_t)err;
    }

    if (col->indexed_field_count > 0) {
        if (old_value) remove_from_indexes(col, key, old_value);
        if (value) update_indexes_for_record(col, key, value);
    }

    if (lookup_err == SMT_ERROR_KEY_NOT_FOUND) {
        col->record_count++;
        db->stats.total_records++;
    } else if (value && old_value && strcmp(value, old_value) != 0) {
        db->stats.total_updates++;
    }

    col->last_modified = time(NULL);
    db->stats.last_modified = col->last_modified;

    if (old_value) free(old_value);
    pthread_rwlock_unlock(&col->lock);

    return DB_SUCCESS;
}

db_error_t db_delete(const char* db_name, const char* collection_name, const char* key) {
    if (!db_name || !collection_name || !key) return DB_ERROR_NULL_POINTER;

    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;

    Collection* col = find_collection(db, collection_name);
    if (!col) return DB_ERROR_COLLECTION_NOT_FOUND;

    pthread_rwlock_wrlock(&col->lock);

    char* old_value = NULL;
    smt_error_t lookup_err = smt_lookup(&col->tree, key, &old_value);

    smt_error_t err = smt_delete(&col->tree, key);
    if (err != SMT_SUCCESS) {
        if (old_value) free(old_value);
        pthread_rwlock_unlock(&col->lock);
        return (db_error_t)err;
    }

    if (lookup_err == SMT_SUCCESS && col->indexed_field_count > 0 && old_value) {
        remove_from_indexes(col, key, old_value);
    }

    col->record_count--;
    db->stats.total_records--;
    col->last_modified = time(NULL);
    db->stats.last_modified = col->last_modified;

    if (old_value) free(old_value);
    pthread_rwlock_unlock(&col->lock);

    return DB_SUCCESS;
}

db_error_t db_batch_insert(const char* db_name, const char* collection_name, const char** keys, const char** values, size_t count) {
    if (!db_name || !collection_name || !keys || !values) return DB_ERROR_NULL_POINTER;
    if (count == 0) return DB_SUCCESS;

    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;

    Collection* col = find_collection(db, collection_name);
    if (!col) return DB_ERROR_COLLECTION_NOT_FOUND;

    pthread_rwlock_wrlock(&col->lock);

    size_t new_records = 0;
    db_error_t final_error = DB_SUCCESS;

    for (size_t i = 0; i < count; i++) {
        if (!keys[i]) {
            final_error = DB_ERROR_NULL_POINTER;
            break;
        }

        char* existing_value = NULL;
        smt_error_t lookup_result = smt_lookup(&col->tree, keys[i], &existing_value);

        smt_error_t err = smt_insert(&col->tree, keys[i], values ? values[i] : NULL);
        if (err != SMT_SUCCESS) {
            final_error = (db_error_t)err;
            if (existing_value) free(existing_value);
            break;
        }

        if (values && values[i] && col->indexed_field_count > 0) {
            update_indexes_for_record(col, keys[i], values[i]);
        }

        if (lookup_result == SMT_ERROR_KEY_NOT_FOUND) {
            new_records++;
        }

        if (existing_value) free(existing_value);
    }

    col->record_count += new_records;
    db->stats.total_records += new_records;
    col->last_modified = time(NULL);
    db->stats.last_modified = col->last_modified;

    pthread_rwlock_unlock(&col->lock);
    return final_error;
}

db_error_t db_find_all(const char* db_name, const char* collection_name, char*** keys, char*** values, size_t* count) {
    if (!db_name || !collection_name || !keys || !values || !count) return DB_ERROR_NULL_POINTER;

    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;

    Collection* col = find_collection(db, collection_name);
    if (!col) return DB_ERROR_COLLECTION_NOT_FOUND;

    pthread_rwlock_rdlock(&col->lock);
    db_error_t err = db_find_all_internal(col, keys, values, count);
    pthread_rwlock_unlock(&col->lock);

    return err;
}

db_error_t db_create_index(const char* db_name, const char* collection_name, const char* field_name) {
    fprintf(stdout, "[DEBUG] db_create_index: Starting for db='%s', collection='%s', field='%s'\n", db_name, collection_name, field_name);
    if (!db_name || !collection_name || !field_name) {
        fprintf(stderr, "[ERROR] db_create_index: Null pointer detected\n");
        return DB_ERROR_NULL_POINTER;
    }

    Database* db = find_database(db_name);
    if (!db) {
        fprintf(stderr, "[ERROR] db_create_index: Database '%s' not found\n", db_name);
        return DB_ERROR_DATABASE_NOT_FOUND;
    }

    Collection* col = find_collection(db, collection_name);
    if (!col) {
        fprintf(stderr, "[ERROR] db_create_index: Collection '%s' not found\n", collection_name);
        return DB_ERROR_COLLECTION_NOT_FOUND;
    }

    fprintf(stdout, "[DEBUG] db_create_index: Acquiring write lock for collection '%s'\n", collection_name);
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += 5; // 5-second timeout
    int lock_err = pthread_rwlock_timedwrlock(&col->lock, &timeout);
    if (lock_err == ETIMEDOUT) {
        fprintf(stderr, "[ERROR] db_create_index: Lock acquisition timed out\n");
        return DB_ERROR_LOCK_TIMEOUT;
    } else if (lock_err != 0) {
        fprintf(stderr, "[ERROR] db_create_index: Lock error %d\n", lock_err);
        return DB_ERROR_LOCK_FAILED;
    }
    fprintf(stdout, "[DEBUG] db_create_index: Write lock acquired\n");

    for (size_t i = 0; i < col->indexed_field_count; i++) {
        if (strcmp(col->indexed_fields[i], field_name) == 0) {
            fprintf(stdout, "[DEBUG] db_create_index: Field '%s' already indexed\n", field_name);
            pthread_rwlock_unlock(&col->lock);
            return DB_SUCCESS;
        }
    }

    if (col->indexed_field_count >= MAX_INDEX_FIELDS) {
        fprintf(stderr, "[ERROR] db_create_index: Max index fields reached\n");
        pthread_rwlock_unlock(&col->lock);
        return DB_ERROR_MAX_LIMIT_REACHED;
    }

    char** keys = NULL;
    char** values = NULL;
    size_t count = 0;
    fprintf(stdout, "[DEBUG] db_create_index: Calling db_find_all_internal\n");
    db_error_t err = db_find_all_internal(col, &keys, &values, &count);
    if (err != DB_SUCCESS) {
        fprintf(stderr, "[ERROR] db_create_index: Failed to retrieve records, error=%d\n", err);
        pthread_rwlock_unlock(&col->lock);
        return err;
    }
    fprintf(stdout, "[DEBUG] db_create_index: Retrieved %zu records\n", count);

    for (size_t i = 0; i < count; i++) {
        fprintf(stdout, "[DEBUG] db_create_index: Processing record %zu: key=%s\n", i, keys[i]);
        json_t* root = json_loads(values[i], 0, NULL);
        if (!root) {
            fprintf(stderr, "[ERROR] db_create_index: Failed to parse JSON for key %s\n", keys[i]);
            continue; // Skip invalid JSON, continue with next record
        }
        fprintf(stdout, "[DEBUG] db_create_index: Parsed JSON for key %s\n", keys[i]);

        json_t* field_value = json_object_get(root, field_name);
        if (field_value && (json_is_string(field_value) || json_is_integer(field_value) || json_is_real(field_value))) {
            const char* val_str = NULL;
            char val_buffer[64] = {0};
            
            if (json_is_string(field_value)) {
                val_str = json_string_value(field_value);
            } else if (json_is_integer(field_value)) {
                snprintf(val_buffer, sizeof(val_buffer), "%lld", (long long)json_integer_value(field_value));
                val_str = val_buffer;
            } else if (json_is_real(field_value)) {
                snprintf(val_buffer, sizeof(val_buffer), "%f", json_real_value(field_value));
                val_str = val_buffer;
            }
            
            if (val_str) {
                char index_key[256];
                if (strlen(field_name) + strlen(val_str) + 10 >= sizeof(index_key)) {
                    fprintf(stderr, "[ERROR] db_create_index: Index key too long for %s:%s\n", field_name, val_str);
                    json_decref(root);
                    continue;
                }
                snprintf(index_key, sizeof(index_key), "__index__:%s:%s", field_name, val_str);
                fprintf(stdout, "[DEBUG] db_create_index: Generated index key: %s\n", index_key);

                char* current_list_str = NULL;
                fprintf(stdout, "[DEBUG] db_create_index: Calling smt_lookup for %s\n", index_key);
                smt_error_t lookup_err = smt_lookup(&col->tree, index_key, &current_list_str);
                fprintf(stdout, "[DEBUG] db_create_index: smt_lookup returned %d\n", lookup_err);

                json_t* list = NULL;
                if (lookup_err == SMT_SUCCESS && current_list_str) {
                    list = json_loads(current_list_str, 0, NULL);
                    free(current_list_str);
                    if (!list) {
                        fprintf(stderr, "[ERROR] db_create_index: Failed to parse current list for %s\n", index_key);
                        json_decref(root);
                        continue;
                    }
                }
                if (!list) {
                    list = json_array();
                }
                json_array_append_new(list, json_string(keys[i]));
                char* new_list_str = json_dumps(list, JSON_COMPACT);
                if (new_list_str) {
                    fprintf(stdout, "[DEBUG] db_create_index: Calling smt_insert for %s\n", index_key);
                    smt_error_t insert_err = smt_insert(&col->tree, index_key, new_list_str);
                    if (insert_err != SMT_SUCCESS) {
                        fprintf(stderr, "[ERROR] db_create_index: smt_insert failed for %s, error=%d\n", index_key, insert_err);
                        free(new_list_str);
                        json_decref(list);
                        json_decref(root);
                        continue;
                    }
                    free(new_list_str);
                } else {
                    fprintf(stderr, "[ERROR] db_create_index: Failed to serialize list for %s\n", index_key);
                }
                json_decref(list);
            }
        } else {
            fprintf(stdout, "[DEBUG] db_create_index: Field %s not found or not indexable in key %s\n", field_name, keys[i]);
        }
        json_decref(root);
    }

    col->indexed_fields[col->indexed_field_count] = strdup(field_name);
    if (!col->indexed_fields[col->indexed_field_count]) {
        fprintf(stderr, "[ERROR] db_create_index: Memory allocation failed for indexed field\n");
        db_free_list(keys, count);
        db_free_list(values, count);
        pthread_rwlock_unlock(&col->lock);
        return DB_ERROR_MEMORY_ALLOCATION;
    }
    col->indexed_field_count++;
    fprintf(stdout, "[DEBUG] db_create_index: Added field '%s' to indexed_fields, count=%zu\n", field_name, col->indexed_field_count);

    db_free_list(keys, count);
    db_free_list(values, count);

    fprintf(stdout, "[DEBUG] db_create_index: Releasing write lock\n");
    pthread_rwlock_unlock(&col->lock);
    fprintf(stdout, "[DEBUG] db_create_index: Successfully created index on '%s'\n", field_name);
    return DB_SUCCESS;
}

db_error_t db_query_by_field(const char* db_name, const char* collection_name,
                            const char* field_name, const char* field_value,
                            char*** keys, size_t* count) {
    if (!db_name || !collection_name || !field_name || !field_value || !keys || !count) {
        return DB_ERROR_NULL_POINTER;
    }

    *keys = NULL;
    *count = 0;

    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;

    Collection* col = find_collection(db, collection_name);
    if (!col) return DB_ERROR_COLLECTION_NOT_FOUND;

    pthread_rwlock_rdlock(&col->lock);

    // Check if field is indexed
    int is_indexed = 0;
    for (size_t i = 0; i < col->indexed_field_count; i++) {
        if (strcmp(col->indexed_fields[i], field_name) == 0) {
            is_indexed = 1;
            break;
        }
    }

    if (!is_indexed) {
        pthread_rwlock_unlock(&col->lock);
        fprintf(stderr, "[ERROR] Field '%s' is not indexed in collection '%s'\n", 
                field_name, collection_name);
        return DB_ERROR_INVALID_PARAMETER;
    }

    char index_key[256];
    snprintf(index_key, sizeof(index_key), "__index__:%s:%s", field_name, field_value);

    char* list_str;
    smt_error_t err = smt_lookup(&col->tree, index_key, &list_str);
    if (err != SMT_SUCCESS) {
        pthread_rwlock_unlock(&col->lock);
        return DB_SUCCESS;  // No matches found is not an error
    }

    json_t* list = json_loads(list_str, 0, NULL);
    free(list_str);
    if (!list || !json_is_array(list)) {
        if (list) json_decref(list);
        pthread_rwlock_unlock(&col->lock);
        return DB_ERROR_INVALID_JSON;
    }

    size_t array_size = json_array_size(list);
    if (array_size == 0) {
        json_decref(list);
        pthread_rwlock_unlock(&col->lock);
        return DB_SUCCESS;
    }

    *keys = malloc(array_size * sizeof(char*));
    if (!*keys) {
        json_decref(list);
        pthread_rwlock_unlock(&col->lock);
        return DB_ERROR_MEMORY_ALLOCATION;
    }

    for (size_t i = 0; i < array_size; i++) {
        json_t* item = json_array_get(list, i);
        if (json_is_string(item)) {
            (*keys)[i] = strdup(json_string_value(item));
            if (!(*keys)[i]) {
                for (size_t j = 0; j < i; j++) {
                    free((*keys)[j]);
                }
                free(*keys);
                *keys = NULL;
                json_decref(list);
                pthread_rwlock_unlock(&col->lock);
                return DB_ERROR_MEMORY_ALLOCATION;
            }
        } else {
            for (size_t j = 0; j < i; j++) {
                free((*keys)[j]);
            }
            free(*keys);
            *keys = NULL;
            json_decref(list);
            pthread_rwlock_unlock(&col->lock);
            return DB_ERROR_INVALID_JSON;
        }
    }

    *count = array_size;
    json_decref(list);
    pthread_rwlock_unlock(&col->lock);
    return DB_SUCCESS;
}


db_error_t db_get_root_hash(const char* db_name, const char* collection_name, unsigned char* root_hash) {
    if (!db_name || !collection_name || !root_hash) return DB_ERROR_NULL_POINTER;

    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;

    Collection* col = find_collection(db, collection_name);
    if (!col) return DB_ERROR_COLLECTION_NOT_FOUND;

    pthread_rwlock_rdlock(&col->lock);
    smt_error_t err = smt_get_root(&col->tree, root_hash);
    pthread_rwlock_unlock(&col->lock);

    return (db_error_t)err;
}

db_error_t db_generate_proof(const char* db_name, const char* collection_name, const char* key, MembershipProof* proof) {
    if (!db_name || !collection_name || !key || !proof) return DB_ERROR_NULL_POINTER;

    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;

    pthread_rwlock_rdlock(&db->lock);
    Collection* col = find_collection(db, collection_name);
    if (!col) {
        pthread_rwlock_unlock(&db->lock);
        return DB_ERROR_COLLECTION_NOT_FOUND;
    }

    pthread_rwlock_rdlock(&col->lock);
    smt_error_t err = smt_generate_proof(&col->tree, key, proof);
    pthread_rwlock_unlock(&col->lock);
    pthread_rwlock_unlock(&db->lock);

    return (db_error_t)err;
}

db_error_t db_verify_proof(const char* db_name, const char* collection_name,
                         const char* key, const char* value,
                         const MembershipProof* proof, int* valid) {
    if (!db_name || !collection_name || !key || !proof || !valid) return DB_ERROR_NULL_POINTER;

    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;

    pthread_rwlock_rdlock(&db->lock);
    Collection* col = find_collection(db, collection_name);
    if (!col) {
        pthread_rwlock_unlock(&db->lock);
        return DB_ERROR_COLLECTION_NOT_FOUND;
    }

    pthread_rwlock_rdlock(&col->lock);
    smt_error_t err = smt_verify_proof(&col->tree, key, value, proof, valid);
    pthread_rwlock_unlock(&col->lock);
    pthread_rwlock_unlock(&db->lock);

    return (db_error_t)err;
}

db_error_t db_save(const char* db_name) {
    if (!db_name) return DB_ERROR_NULL_POINTER;
    if (!g_db_manager.is_initialized) return DB_ERROR_INVALID_PARAMETER;
    if (g_db_manager.persistence_path[0] == '\0') return DB_ERROR_IO_ERROR;

    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;

    char path[2048];
    snprintf(path, sizeof(path), "%s/%s.smtdb", g_db_manager.persistence_path, db_name);

    char temp_path[2048];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

    int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) return DB_ERROR_IO_ERROR;

    db_error_t err = serialize_database(db, fd);
    close(fd);

    if (err != DB_SUCCESS) {
        unlink(temp_path);
        return err;
    }

    if (rename(temp_path, path) == -1) {
        unlink(temp_path);
        return DB_ERROR_IO_ERROR;
    }

    return DB_SUCCESS;
}

db_error_t db_load(const char* db_name) {
    if (!db_name) return DB_ERROR_NULL_POINTER;
    if (!g_db_manager.is_initialized) return DB_ERROR_INVALID_PARAMETER;
    if (g_db_manager.persistence_path[0] == '\0') return DB_ERROR_IO_ERROR;

    char path[2048];
    snprintf(path, sizeof(path), "%s/%s.smtdb", g_db_manager.persistence_path, db_name);

    int fd = open(path, O_RDONLY);
    if (fd == -1) return DB_ERROR_IO_ERROR;

    db_error_t err = db_create(db_name);
    if (err != DB_SUCCESS && err != DB_ERROR_DATABASE_EXISTS) {
        close(fd);
        return err;
    }

    Database* db = find_database(db_name);
    if (!db) {
        close(fd);
        return DB_ERROR_DATABASE_NOT_FOUND;
    }

    pthread_rwlock_wrlock(&db->lock);
    err = deserialize_database(db, fd);
    pthread_rwlock_unlock(&db->lock);

    close(fd);
    return err;
}

db_error_t db_save_all() {
    if (!g_db_manager.is_initialized) return DB_ERROR_INVALID_PARAMETER;
    if (g_db_manager.persistence_path[0] == '\0') return DB_ERROR_IO_ERROR;

    pthread_mutex_lock(&g_db_manager.lock);

    char* db_names[MAX_DATABASES];
    size_t db_count = 0;
    for (size_t i = 0; i < g_db_manager.db_count; i++) {
        if (g_db_manager.databases[i].is_open) {
            db_names[db_count] = strdup(g_db_manager.databases[i].name);
            if (!db_names[db_count]) {
                for (size_t j = 0; j < db_count; j++) {
                    free(db_names[j]);
                }
                pthread_mutex_unlock(&g_db_manager.lock);
                return DB_ERROR_MEMORY_ALLOCATION;
            }
            db_count++;
        }
    }

    pthread_mutex_unlock(&g_db_manager.lock);

    db_error_t final_error = DB_SUCCESS;
    for (size_t i = 0; i < db_count; i++) {
        db_error_t err = db_save(db_names[i]);
        if (err != DB_SUCCESS) {
            final_error = err;
            for (size_t j = i; j < db_count; j++) {
                free(db_names[j]);
            }
            break;
        }
        free(db_names[i]);
    }

    return final_error;
}

db_error_t db_load_all() {
    if (!g_db_manager.is_initialized) return DB_ERROR_INVALID_PARAMETER;
    if (g_db_manager.persistence_path[0] == '\0') return DB_ERROR_IO_ERROR;

    DIR* dir = opendir(g_db_manager.persistence_path);
    if (!dir) return DB_ERROR_IO_ERROR;

    struct dirent* entry;
    db_error_t final_error = DB_SUCCESS;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && strlen(entry->d_name) > 7 && 
            strcmp(entry->d_name + strlen(entry->d_name) - 7, ".smtdb") == 0) {
            char db_name[MAX_DB_NAME_LEN];
            strncpy(db_name, entry->d_name, strlen(entry->d_name) - 7);
            db_name[strlen(entry->d_name) - 7] = '\0';

            db_error_t err = db_load(db_name);
            if (err != DB_SUCCESS) {
                final_error = err;
                break;
            }
        }
    }

    closedir(dir);
    return final_error;
}

const char* db_error_string(db_error_t error) {
    switch (error) {
        case DB_SUCCESS: return "Success";
        case DB_ERROR_NULL_POINTER: return "Null pointer";
        case DB_ERROR_MEMORY_ALLOCATION: return "Memory allocation failed";
        case DB_ERROR_INVALID_PARAMETER: return "Invalid parameter";
        case DB_ERROR_KEY_NOT_FOUND: return "Key not found";
        case DB_ERROR_DATABASE_NOT_FOUND: return "Database not found";
        case DB_ERROR_COLLECTION_NOT_FOUND: return "Collection not found";
        case DB_ERROR_DATABASE_EXISTS: return "Database already exists";
        case DB_ERROR_COLLECTION_EXISTS: return "Collection already exists";
        case DB_ERROR_MAX_LIMIT_REACHED: return "Maximum limit reached";
        case DB_ERROR_INVALID_JSON: return "Invalid JSON format";
        case DB_ERROR_CONCURRENT_ACCESS: return "Concurrent access error";
        case DB_ERROR_DATABASE_CLOSED: return "Database is closed";
        case DB_ERROR_IO_ERROR: return "I/O error";
        case DB_ERROR_CORRUPTED_DATA: return "Corrupted data";
        default: return "Unknown error";
    }
}

db_error_t db_compact(const char* db_name) {
    return DB_SUCCESS;
}

db_error_t db_verify_integrity(const char* db_name, json_t** verification_results) {
    if (!db_name || !verification_results) return DB_ERROR_NULL_POINTER;

    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;

    pthread_rwlock_rdlock(&db->lock);

    db_error_t final_error = DB_SUCCESS;
    *verification_results = json_array();

    for (size_t i = 0; i < db->collection_count; i++) {
        Collection* col = &db->collections[i];
        if (!col->is_open) continue;

        pthread_rwlock_rdlock(&col->lock);

        unsigned char root_hash[HASH_SIZE];
        smt_error_t err = smt_get_root(&col->tree, root_hash);
        if (err != SMT_SUCCESS) {
            final_error = (db_error_t)err;
            pthread_rwlock_unlock(&col->lock);
            json_decref(*verification_results);
            *verification_results = NULL;
            pthread_rwlock_unlock(&db->lock);
            return final_error;
        }

        char hash_str[2*HASH_SIZE+1];
        for (size_t j = 0; j < HASH_SIZE; j++) {
            sprintf(hash_str + 2*j, "%02x", root_hash[j]);
        }

        json_t* result = json_object();
        json_object_set_new(result, "collection", json_string(col->name));
        json_object_set_new(result, "root_hash", json_string(hash_str));
        json_array_append_new(*verification_results, result);

        pthread_rwlock_unlock(&col->lock);
    }

    pthread_rwlock_unlock(&db->lock);
    return final_error;
}

void db_free_list(char** list, size_t count) {
    if (list) {
        for (size_t i = 0; i < count; i++) {
            free(list[i]);
        }
        free(list);
    }
}