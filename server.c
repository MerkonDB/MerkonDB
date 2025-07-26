#include "smt_db.h"
#include "rbac.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <jansson.h>
#include <arpa/inet.h>
#include "common.h"
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

// Include original smt_db.c functions
//#include "smt_db.c"

#define DEFAULT_PORT 8080
#define BUFFER_SIZE 4096
#define MAX_DATABASES 10

static int server_fd = -1;
static RBACSystem g_rbac;

static int read_message(int fd, char** message) {
    uint32_t length;
    if (read(fd, &length, sizeof(length)) != sizeof(length)) return -1;
    length = ntohl(length);
    if (length > BUFFER_SIZE) return -1; // Prevent buffer overflow
    *message = malloc(length + 1);
    if (!*message) return -1;
    if (read(fd, *message, length) != length) {
        free(*message);
        return -1;
    }
    (*message)[length] = '\0';
    return 0;
}

static int write_message(int fd, const char* message) {
    uint32_t length = strlen(message);
    uint32_t net_length = htonl(length);
    if (write(fd, &net_length, sizeof(net_length)) != sizeof(net_length)) return -1;
    if (write(fd, message, length) != length) return -1;
    return 0;
}

static json_t* proof_to_json(const MembershipProof* proof) {
    json_t* obj = json_object();
    json_object_set_new(obj, "layer_priority", json_integer(proof->layer_priority));
    json_object_set_new(obj, "element_index", json_integer(proof->element_index));
    char layer_root_str[2*HASH_SIZE+1];
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(layer_root_str + 2*i, "%02x", proof->layer_root[i]);
    }
    json_object_set_new(obj, "layer_root", json_string(layer_root_str));
    if (proof->layer_proof_len > 0) {
        char* layer_proof_str = malloc(2 * proof->layer_proof_len + 1);
        for (size_t i = 0; i < proof->layer_proof_len; i++) {
            sprintf(layer_proof_str + 2*i, "%02x", proof->layer_proof[i]);
        }
        json_object_set_new(obj, "layer_proof", json_string(layer_proof_str));
        free(layer_proof_str);
    } else {
        json_object_set_new(obj, "layer_proof", json_string(""));
    }
    if (proof->top_level_proof_len > 0) {
        char* top_level_proof_str = malloc(2 * proof->top_level_proof_len + 1);
        for (size_t i = 0; i < proof->top_level_proof_len; i++) {
            sprintf(top_level_proof_str + 2*i, "%02x", proof->top_level_proof[i]);
        }
        json_object_set_new(obj, "top_level_proof", json_string(top_level_proof_str));
        free(top_level_proof_str);
    } else {
        json_object_set_new(obj, "top_level_proof", json_string(""));
    }
    return obj;
}

static db_error_t json_to_proof(json_t* json, MembershipProof* proof) {
    memset(proof, 0, sizeof(MembershipProof));
    proof->layer_priority = json_integer_value(json_object_get(json, "layer_priority"));
    proof->element_index = json_integer_value(json_object_get(json, "element_index"));
    const char* layer_root_str = json_string_value(json_object_get(json, "layer_root"));
    for (int i = 0; i < HASH_SIZE; i++) {
        sscanf(layer_root_str + 2*i, "%2hhx", &proof->layer_root[i]);
    }
    const char* layer_proof_str = json_string_value(json_object_get(json, "layer_proof"));
    proof->layer_proof_len = strlen(layer_proof_str) / 2;
    if (proof->layer_proof_len > 0) {
        proof->layer_proof = malloc(proof->layer_proof_len);
        if (!proof->layer_proof) return DB_ERROR_MEMORY_ALLOCATION;
        for (size_t i = 0; i < proof->layer_proof_len; i++) {
            sscanf(layer_proof_str + 2*i, "%2hhx", &proof->layer_proof[i]);
        }
    }
    const char* top_proof_str = json_string_value(json_object_get(json, "top_level_proof"));
    proof->top_level_proof_len = strlen(top_proof_str) / 2;
    if (proof->top_level_proof_len > 0) {
        proof->top_level_proof = malloc(proof->top_level_proof_len);
        if (!proof->top_level_proof) {
            free(proof->layer_proof);
            return DB_ERROR_MEMORY_ALLOCATION;
        }
        for (size_t i = 0; i < proof->top_level_proof_len; i++) {
            sscanf(top_proof_str + 2*i, "%2hhx", &proof->top_level_proof[i]);
        }
    }
    return DB_SUCCESS;
}

static json_t* stats_to_json(const DatabaseStats* stats) {
    json_t* obj = json_object();
    json_object_set_new(obj, "total_records", json_integer(stats->total_records));
    json_object_set_new(obj, "total_collections", json_integer(stats->total_collections));
    json_object_set_new(obj, "created_at", json_integer(stats->created_at));
    json_object_set_new(obj, "total_updates", json_integer(stats->total_updates));
    json_object_set_new(obj, "last_modified", json_integer(stats->last_modified));
    char root_hash_str[2*HASH_SIZE+1];
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(root_hash_str + 2*i, "%02x", stats->root_hash[i]);
    }
    json_object_set_new(obj, "root_hash", json_string(root_hash_str));
    json_object_set_new(obj, "memory_usage_bytes", json_integer(stats->memory_usage_bytes));
    return obj;
}

static void* client_handler(void* arg) {
    int client_fd = (int)(intptr_t)arg;
    char* message = NULL;
    json_error_t error;
    const char* client_ip = "unknown";
    char* username = NULL;
    time_t now;
    char timestamp[32];

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername(client_fd, (struct sockaddr*)&addr, &addr_len) == 0) {
        client_ip = inet_ntoa(addr.sin_addr);
    }

    time(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    printf("[%s] [CONNECT] New connection from %s (FD: %d)\n", timestamp, client_ip, client_fd);

    if (read_message(client_fd, &message) != 0) {
        printf("[%s] [ERROR] Failed to read auth message from %s (FD: %d)\n", timestamp, client_ip, client_fd);
        close(client_fd);
        return NULL;
    }

    printf("[%s] [DEBUG] Auth message from %s: %.*s\n", timestamp, client_ip, (int)(message ? strnlen(message, 256) : 0), message ? message : "NULL");

    json_t* auth = json_loads(message, 0, &error);
    free(message);
    message = NULL;

    if (!auth) {
        json_t* response = json_object();
        json_object_set_new(response, "status", json_string("error"));
        json_object_set_new(response, "error_message", json_string("Invalid authentication JSON"));
        char* resp_str = json_dumps(response, JSON_COMPACT);
        if (resp_str) {
            write_message(client_fd, resp_str);
            free(resp_str);
        }
        json_decref(response);
        close(client_fd);
        return NULL;
    }

    json_t* auth_obj = json_object_get(auth, "auth");
    if (!auth_obj || !json_is_object(auth_obj)) {
        json_t* response = json_object();
        json_object_set_new(response, "status", json_string("error"));
        json_object_set_new(response, "error_message", json_string("Missing or invalid auth object"));
        char* resp_str = json_dumps(response, JSON_COMPACT);
        if (resp_str) {
            write_message(client_fd, resp_str);
            free(resp_str);
        }
        json_decref(response);
        json_decref(auth);
        close(client_fd);
        return NULL;
    }

    const char* temp_username = json_string_value(json_object_get(auth_obj, "username"));
    const char* password = json_string_value(json_object_get(auth_obj, "password"));

    if (!temp_username || !password) {
        json_t* response = json_object();
        json_object_set_new(response, "status", json_string("error"));
        json_object_set_new(response, "error_message", json_string("Username and password required"));
        char* resp_str = json_dumps(response, JSON_COMPACT);
        if (resp_str) {
            write_message(client_fd, resp_str);
            free(resp_str);
        }
        json_decref(response);
        json_decref(auth);
        close(client_fd);
        return NULL;
    }

    username = strdup(temp_username);
    if (!username) {
        json_t* response = json_object();
        json_object_set_new(response, "status", json_string("error"));
        json_object_set_new(response, "error_message", json_string("Server memory error"));
        char* resp_str = json_dumps(response, JSON_COMPACT);
        if (resp_str) {
            write_message(client_fd, resp_str);
            free(resp_str);
        }
        json_decref(response);
        json_decref(auth);
        close(client_fd);
        return NULL;
    }

    printf("[%s] [AUTH] Attempt for user '%s' from %s\n", timestamp, username, client_ip);

    int auth_result = rbac_authenticate_user(&g_rbac, username, password);
    if (auth_result != 0) {
        json_t* response = json_object();
        json_object_set_new(response, "status", json_string("error"));
        json_object_set_new(response, "error_message", json_string("Authentication failed"));
        char* resp_str = json_dumps(response, JSON_COMPACT);
        if (resp_str) {
            write_message(client_fd, resp_str);
            free(resp_str);
        }
        json_decref(response);
        json_decref(auth);
        free(username);
        close(client_fd);
        return NULL;
    }

    printf("[%s] [AUTH] Success for user '%s' from %s\n", timestamp, username, client_ip);

    json_t* auth_response = json_object();
    json_object_set_new(auth_response, "status", json_string("success"));
    char* auth_resp_str = json_dumps(auth_response, JSON_COMPACT);
    if (auth_resp_str) {
        if (write_message(client_fd, auth_resp_str) != 0) {
            printf("[%s] [ERROR] Failed to send auth response to %s\n", timestamp, client_ip);
            free(auth_resp_str);
            json_decref(auth_response);
            json_decref(auth);
            free(username);
            close(client_fd);
            return NULL;
        }
        free(auth_resp_str);
    }
    json_decref(auth_response);
    json_decref(auth);

    while (1) {
        time(&now);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

        int read_result = read_message(client_fd, &message);
        if (read_result != 0) {
            printf("[%s] [DISCONNECT] Client %s (user: %s) closed connection\n", timestamp, client_ip, username ? username : "unknown");
            break;
        }

        printf("[%s] [DEBUG] Message from %s (user: %s): %.*s\n", timestamp, client_ip, username ? username : "unknown", (int)(message ? strnlen(message, 256) : 0), message ? message : "NULL");

        json_t* root = json_loads(message, 0, &error);
        free(message);
        message = NULL;

        if (!root) {
            json_t* response = json_object();
            json_object_set_new(response, "status", json_string("error"));
            json_object_set_new(response, "error_message", json_string("Invalid JSON"));
            char* resp_str = json_dumps(response, JSON_COMPACT);
            if (resp_str) {
                write_message(client_fd, resp_str);
                free(resp_str);
            }
            json_decref(response);
            continue;
        }

        json_t* op_json = json_object_get(root, "operation");
        if (!op_json || !json_is_string(op_json)) {
            json_t* response = json_object();
            json_object_set_new(response, "status", json_string("error"));
            json_object_set_new(response, "error_message", json_string("Missing or invalid operation"));
            char* resp_str = json_dumps(response, JSON_COMPACT);
            if (resp_str) {
                write_message(client_fd, resp_str);
                free(resp_str);
            }
            json_decref(response);
            json_decref(root);
            continue;
        }

        const char* operation = json_string_value(op_json);
        json_t* params = json_object_get(root, "params");
        json_t* response = json_object();

        printf("[%s] [OP] %s from %s (user: %s)\n", timestamp, operation, client_ip, username ? username : "unknown");

        int required_perm = PERM_NONE;
        if (strcmp(operation, "rbac_add_user") == 0 || 
            strcmp(operation, "rbac_add_role") == 0 ||
            strcmp(operation, "rbac_assign_role") == 0 ||
            strcmp(operation, "rbac_remove_user") == 0 ||
            strcmp(operation, "rbac_remove_role") == 0 ||
            strcmp(operation, "rbac_revoke_role") == 0) {
            required_perm = PERM_ADMIN;
        } else if (strstr(operation, "find") || strstr(operation, "list") || strstr(operation, "get") || strcmp(operation, "db_query_by_field") == 0) {
            required_perm = PERM_READ;
        } else if (strstr(operation, "insert") || strstr(operation, "update") || 
                   strstr(operation, "create") || strstr(operation, "open") || strcmp(operation, "db_create_index") == 0) {
            required_perm = PERM_WRITE;
        } else if (strstr(operation, "delete") || strstr(operation, "drop") || 
                   strstr(operation, "close")) {
            required_perm = PERM_DELETE;
        }

        const char* db_name = json_string_value(json_object_get(params, "db_name"));
        if (required_perm != PERM_NONE && required_perm != PERM_ADMIN && db_name) {
            if (!rbac_has_db_permission(&g_rbac, username, db_name, required_perm)) {
                printf("[%s] [AUTH] Denied %s on %s for %s\n", timestamp, operation, db_name, username ? username : "unknown");
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string("Permission denied"));
                char* resp_str = json_dumps(response, JSON_COMPACT);
                if (resp_str) {
                    write_message(client_fd, resp_str);
                    free(resp_str);
                }
                json_decref(response);
                json_decref(root);
                continue;
            }
        } else if (required_perm == PERM_ADMIN) {
            if (!rbac_has_permission(&g_rbac, username, PERM_ADMIN)) {
                printf("[%s] [AUTH] Admin denied for %s\n", timestamp, username ? username : "unknown");
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string("Permission denied"));
                char* resp_str = json_dumps(response, JSON_COMPACT);
                if (resp_str) {
                    write_message(client_fd, resp_str);
                    free(resp_str);
                }
                json_decref(response);
                json_decref(root);
                continue;
            }
        }

        // RBAC operations (unchanged)
        if (strcmp(operation, "rbac_add_user") == 0) {
            const char* new_username = json_string_value(json_object_get(params, "username"));
            const char* password = json_string_value(json_object_get(params, "password"));
            if (!new_username || !password) {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string("Invalid parameters"));
            } else if (rbac_add_user(&g_rbac, new_username, password) != 0) {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string("Failed to add user"));
            } else {
                json_object_set_new(response, "status", json_string("success"));
            }
        } else if (strcmp(operation, "rbac_add_role") == 0) {
            const char* role_name = json_string_value(json_object_get(params, "role_name"));
            int permissions = json_integer_value(json_object_get(params, "permissions"));
            if (!role_name) {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string("Invalid parameters"));
            } else if (rbac_add_role(&g_rbac, role_name, permissions) != 0) {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string("Failed to add role"));
            } else {
                json_object_set_new(response, "status", json_string("success"));
            }
        } else if (strcmp(operation, "rbac_assign_role") == 0) {
            const char* new_username = json_string_value(json_object_get(params, "username"));
            const char* role_name = json_string_value(json_object_get(params, "role_name"));
            if (!new_username || !role_name) {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string("Invalid parameters"));
            } else if (rbac_assign_role(&g_rbac, new_username, role_name) != 0) {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string("Failed to assign role"));
            } else {
                json_object_set_new(response, "status", json_string("success"));
            }
        } else if (strcmp(operation, "rbac_remove_user") == 0) {
            const char* new_username = json_string_value(json_object_get(params, "username"));
            if (!new_username) {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string("Invalid parameters"));
            } else if (rbac_remove_user(&g_rbac, new_username) != 0) {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string("Failed to remove user"));
            } else {
                json_object_set_new(response, "status", json_string("success"));
            }
        } else if (strcmp(operation, "rbac_remove_role") == 0) {
            const char* role_name = json_string_value(json_object_get(params, "role_name"));
            if (!role_name) {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string("Invalid parameters"));
            } else if (rbac_remove_role(&g_rbac, role_name) != 0) {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string("Failed to remove role"));
            } else {
                json_object_set_new(response, "status", json_string("success"));
            }
        } else if (strcmp(operation, "rbac_revoke_role") == 0) {
            const char* new_username = json_string_value(json_object_get(params, "username"));
            const char* role_name = json_string_value(json_object_get(params, "role_name"));
            if (!new_username || !role_name) {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string("Invalid parameters"));
            } else if (rbac_revoke_role(&g_rbac, new_username, role_name) != 0) {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string("Failed to revoke role"));
            } else {
                json_object_set_new(response, "status", json_string("success"));
            }
        }
        // New index operations
        else if (strcmp(operation, "db_create_index") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            const char* collection_name = json_string_value(json_object_get(params, "collection_name"));
            const char* field_name = json_string_value(json_object_get(params, "field_name"));
            if (!db_name || !collection_name || !field_name) {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string("Missing required parameters"));
            } else {
                db_error_t err = db_create_index(db_name, collection_name, field_name);
                if (err == DB_SUCCESS) {
                    json_object_set_new(response, "status", json_string("success"));
                } else {
                    json_object_set_new(response, "status", json_string("error"));
                    json_object_set_new(response, "error_message", json_string(db_error_string(err)));
                }
            }
        } else if (strcmp(operation, "db_query_by_field") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            const char* collection_name = json_string_value(json_object_get(params, "collection_name"));
            const char* field_name = json_string_value(json_object_get(params, "field_name"));
            const char* field_value = json_string_value(json_object_get(params, "field_value"));
            if (!db_name || !collection_name || !field_name || !field_value) {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string("Missing required parameters"));
            } else {
                char** keys;
                size_t count;
                db_error_t err = db_query_by_field(db_name, collection_name, field_name, field_value, &keys, &count);
                if (err == DB_SUCCESS) {
                    json_t* keys_array = json_array();
                    for (size_t i = 0; i < count; i++) {
                        json_array_append_new(keys_array, json_string(keys[i]));
                    }
                    json_object_set_new(response, "status", json_string("success"));
                    json_object_set_new(response, "keys", keys_array);
                    db_free_list(keys, count);
                } else {
                    json_object_set_new(response, "status", json_string("error"));
                    json_object_set_new(response, "error_message", json_string(db_error_string(err)));
                }
            }
        }
        // Existing operations (unchanged)
        else if (strcmp(operation, "db_create") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            db_error_t err = db_create(db_name);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_open") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            db_error_t err = db_open(db_name);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_close") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            db_error_t err = db_close(db_name);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_drop") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            db_error_t err = db_drop(db_name);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_exists") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            int exists;
            db_error_t err = db_exists(db_name, &exists);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
                json_object_set_new(response, "exists", json_boolean(exists));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_list") == 0) {
            char** db_names;
            size_t count;
            db_error_t err = db_list(&db_names, &count);
            if (err == DB_SUCCESS) {
                json_t* dbs = json_array();
                for (size_t i = 0; i < count; i++) {
                    json_array_append_new(dbs, json_string(db_names[i]));
                }
                json_object_set_new(response, "status", json_string("success"));
                json_object_set_new(response, "databases", dbs);
                db_free_list(db_names, count);
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_get_stats") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            DatabaseStats stats;
            db_error_t err = db_get_stats(db_name, &stats);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
                json_object_set_new(response, "stats", stats_to_json(&stats));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_create_collection") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            const char* collection_name = json_string_value(json_object_get(params, "collection_name"));
            db_error_t err = db_create_collection(db_name, collection_name);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_drop_collection") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            const char* collection_name = json_string_value(json_object_get(params, "collection_name"));
            db_error_t err = db_drop_collection(db_name, collection_name);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_list_collections") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            char** collection_names;
            size_t count;
            db_error_t err = db_list_collections(db_name, &collection_names, &count);
            if (err == DB_SUCCESS) {
                json_t* cols = json_array();
                for (size_t i = 0; i < count; i++) {
                    json_array_append_new(cols, json_string(collection_names[i]));
                }
                json_object_set_new(response, "status", json_string("success"));
                json_object_set_new(response, "collections", cols);
                db_free_list(collection_names, count);
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_collection_exists") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            const char* collection_name = json_string_value(json_object_get(params, "collection_name"));
            int exists;
            db_error_t err = db_collection_exists(db_name, collection_name, &exists);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
                json_object_set_new(response, "exists", json_boolean(exists));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_insert") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            const char* collection_name = json_string_value(json_object_get(params, "collection_name"));
            const char* key = json_string_value(json_object_get(params, "key"));
            const char* value = json_string_value(json_object_get(params, "value"));
            db_error_t err = db_insert(db_name, collection_name, key, value);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_find") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            const char* collection_name = json_string_value(json_object_get(params, "collection_name"));
            const char* key = json_string_value(json_object_get(params, "key"));
            char* value;
            db_error_t err = db_find(db_name, collection_name, key, &value);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
                json_object_set_new(response, "value", value ? json_string(value) : json_null());
                free(value);
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_update") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            const char* collection_name = json_string_value(json_object_get(params, "collection_name"));
            const char* key = json_string_value(json_object_get(params, "key"));
            const char* value = json_string_value(json_object_get(params, "value"));
            db_error_t err = db_update(db_name, collection_name, key, value);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_delete") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            const char* collection_name = json_string_value(json_object_get(params, "collection_name"));
            const char* key = json_string_value(json_object_get(params, "key"));
            db_error_t err = db_delete(db_name, collection_name, key);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_batch_insert") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            const char* collection_name = json_string_value(json_object_get(params, "collection_name"));
            json_t* keys = json_object_get(params, "keys");
            json_t* values = json_object_get(params, "values");
            size_t count = json_array_size(keys);
            const char** c_keys = malloc(count * sizeof(char*));
            const char** c_values = malloc(count * sizeof(char*));
            for (size_t i = 0; i < count; i++) {
                c_keys[i] = json_string_value(json_array_get(keys, i));
                c_values[i] = json_string_value(json_array_get(values, i));
            }
            db_error_t err = db_batch_insert(db_name, collection_name, c_keys, c_values, count);
            free(c_keys);
            free(c_values);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_find_all") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            const char* collection_name = json_string_value(json_object_get(params, "collection_name"));
            char** keys;
            char** values;
            size_t count;
            db_error_t err = db_find_all(db_name, collection_name, &keys, &values, &count);
            if (err == DB_SUCCESS) {
                json_t* keys_array = json_array();
                json_t* values_array = json_array();
                for (size_t i = 0; i < count; i++) {
                    json_array_append_new(keys_array, json_string(keys[i]));
                    json_array_append_new(values_array, values[i] ? json_string(values[i]) : json_null());
                }
                json_object_set_new(response, "status", json_string("success"));
                json_object_set_new(response, "keys", keys_array);
                json_object_set_new(response, "values", values_array);
                db_free_list(keys, count);
                db_free_list(values, count);
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_get_root_hash") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            const char* collection_name = json_string_value(json_object_get(params, "collection_name"));
            unsigned char root_hash[HASH_SIZE];
            db_error_t err = db_get_root_hash(db_name, collection_name, root_hash);
            if (err == DB_SUCCESS) {
                char hash_str[2*HASH_SIZE+1];
                for (int i = 0; i < HASH_SIZE; i++) {
                    sprintf(hash_str + 2*i, "%02x", root_hash[i]);
                }
                json_object_set_new(response, "status", json_string("success"));
                json_object_set_new(response, "root_hash", json_string(hash_str));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_generate_proof") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            const char* collection_name = json_string_value(json_object_get(params, "collection_name"));
            const char* key = json_string_value(json_object_get(params, "key"));
            MembershipProof proof;
            db_error_t err = db_generate_proof(db_name, collection_name, key, &proof);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
                json_object_set_new(response, "proof", proof_to_json(&proof));
                membership_proof_cleanup(&proof);
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_verify_proof") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            const char* collection_name = json_string_value(json_object_get(params, "collection_name"));
            const char* key = json_string_value(json_object_get(params, "key"));
            const char* value = json_string_value(json_object_get(params, "value"));
            json_t* proof_json = json_object_get(params, "proof");
            MembershipProof proof;
            db_error_t err = json_to_proof(proof_json, &proof);
            if (err == DB_SUCCESS) {
                int valid;
                err = db_verify_proof(db_name, collection_name, key, value, &proof, &valid);
                if (err == DB_SUCCESS) {
                    json_object_set_new(response, "status", json_string("success"));
                    json_object_set_new(response, "valid", json_boolean(valid));
                } else {
                    json_object_set_new(response, "status", json_string("error"));
                    json_object_set_new(response, "error_message", json_string(db_error_string(err)));
                }
                membership_proof_cleanup(&proof);
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_save") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            db_error_t err = db_save(db_name);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_load") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            db_error_t err = db_load(db_name);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_save_all") == 0) {
            db_error_t err = db_save_all();
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_load_all") == 0) {
            db_error_t err = db_load_all();
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_compact") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            db_error_t err = db_compact(db_name);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
            }
        } else if (strcmp(operation, "db_verify_integrity") == 0) {
            const char* db_name = json_string_value(json_object_get(params, "db_name"));
            json_t* verification_results = NULL;
            db_error_t err = db_verify_integrity(db_name, &verification_results);
            if (err == DB_SUCCESS) {
                json_object_set_new(response, "status", json_string("success"));
                json_object_set_new(response, "verification_results", verification_results ? verification_results : json_array());
            } else {
                json_object_set_new(response, "status", json_string("error"));
                json_object_set_new(response, "error_message", json_string(db_error_string(err)));
                if (verification_results) {
                    json_decref(verification_results);
                }
            }
        } 
        else if (strcmp(operation, "db_list_indexes") == 0) {
    const char* db_name = json_string_value(json_object_get(params, "db_name"));
    const char* collection_name = json_string_value(json_object_get(params, "collection_name"));
    if (!db_name || !collection_name) {
        json_object_set_new(response, "status", json_string("error"));
        json_object_set_new(response, "error_message", json_string("Missing required parameters"));
    } else if (!rbac_has_db_permission(&g_rbac, username, db_name, PERM_READ)) {
        json_object_set_new(response, "status", json_string("error"));
        json_object_set_new(response, "error_message", json_string("Permission denied"));
    } else {
        char** indexed_fields;
        size_t count;
        db_error_t err = db_list_indexes(db_name, collection_name, &indexed_fields, &count);
        if (err == DB_SUCCESS) {
            json_t* fields_array = json_array();
            for (size_t i = 0; i < count; i++) {
                json_array_append_new(fields_array, json_string(indexed_fields[i]));
                free(indexed_fields[i]);
            }
            free(indexed_fields);
            json_object_set_new(response, "status", json_string("success"));
            json_object_set_new(response, "indexed_fields", fields_array);
        } else {
            json_object_set_new(response, "status", json_string("error"));
            json_object_set_new(response, "error_message", json_string(db_error_string(err)));
        }
    }
}
else if (strcmp(operation, "db_drop_index") == 0) {
    const char* db_name = json_string_value(json_object_get(params, "db_name"));
    const char* collection_name = json_string_value(json_object_get(params, "collection_name"));
    const char* field_name = json_string_value(json_object_get(params, "field_name"));
    if (!db_name || !collection_name || !field_name) {
        json_object_set_new(response, "status", json_string("error"));
        json_object_set_new(response, "error_message", json_string("Missing required parameters"));
    } else if (!rbac_has_db_permission(&g_rbac, username, db_name, PERM_WRITE)) {
        json_object_set_new(response, "status", json_string("error"));
        json_object_set_new(response, "error_message", json_string("Permission denied"));
    } else {
        db_error_t err = db_drop_index(db_name, collection_name, field_name);
        if (err == DB_SUCCESS) {
            json_object_set_new(response, "status", json_string("success"));
        } else {
            json_object_set_new(response, "status", json_string("error"));
            json_object_set_new(response, "error_message", json_string(db_error_string(err)));
        }
    }
}


        else {
            json_object_set_new(response, "status", json_string("error"));
            json_object_set_new(response, "error_message", json_string("Unknown operation"));
        }

        time(&now);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

        printf("[%s] [DEBUG] Preparing response for operation '%s'\n", timestamp, operation);
        char* resp_str = json_dumps(response, JSON_COMPACT);
        if (resp_str) {
            printf("[%s] [DEBUG] Response to %s: %.*s\n", timestamp, client_ip, (int)strnlen(resp_str, 256), resp_str);
            if (write_message(client_fd, resp_str) != 0) {
                printf("[%s] [ERROR] Failed to send response to %s for operation '%s'\n", timestamp, client_ip, operation);
                free(resp_str);
                json_decref(response);
                json_decref(root);
                break;
            }
            free(resp_str);
        } else {
            const char* fallback = "{\"status\":\"error\",\"error_message\":\"Server failed to serialize response\"}";
            printf("[%s] [DEBUG] Fallback response to %s: %s\n", timestamp, client_ip, fallback);
            if (write_message(client_fd, fallback) != 0) {
                printf("[%s] [ERROR] Failed to send fallback response to %s for operation '%s'\n", timestamp, client_ip, operation);
                json_decref(response);
                json_decref(root);
                break;
            }
        }

        if (strncmp(operation, "rbac_", 5) == 0 && strcmp(json_string_value(json_object_get(response, "status")), "success") == 0) {
            printf("[%s] [DEBUG] Saving RBAC state after %s\n", timestamp, operation);
            char rbac_path[2048];
            snprintf(rbac_path, sizeof(rbac_path), "%s/rbac.json", g_db_manager.persistence_path);
            if (rbac_save(&g_rbac, rbac_path) != 0) {
                printf("[%s] [WARNING] Failed to save RBAC state after %s\n", timestamp, operation);
            } else {
                printf("[%s] [DEBUG] RBAC state saved successfully\n", timestamp);
            }
        }

        json_decref(response);
        json_decref(root);
    }

    if (message) {
        free(message);
    }

    printf("[%s] [DISCONNECT] Closing connection for %s (user: %s)\n", timestamp, client_ip, username ? username : "unknown");
    free(username);
    close(client_fd);
    return NULL;
}

static void signal_handler(int sig) {
    printf("\nServer shutting down (Signal: %d)...\n", sig);
    
    // Stop autosave first
    db_autosave_stop();
    
    // Save all data
    db_error_t save_err = db_save_all();
    if (save_err != DB_SUCCESS) {
        fprintf(stderr, "Failed to save databases: %s\n", db_error_string(save_err));
    }
    
    // Save RBAC state
    char rbac_path[1024];
    snprintf(rbac_path, sizeof(rbac_path), "%s/rbac.json", g_db_manager.persistence_path);
    if (rbac_save(&g_rbac, rbac_path) != 0) {
        fprintf(stderr, "Failed to save RBAC state\n");
    }
    
    // Cleanup
    if (server_fd >= 0) {
        close(server_fd);
    }
    db_manager_cleanup();
    rbac_cleanup(&g_rbac);
    
    exit(0);
}

// Enhanced db_recover_all function
db_error_t db_recover_all() {
    if (!g_db_manager.is_initialized) {
        return DB_ERROR_INVALID_PARAMETER;
    }
    
    // 1. Load database structure from metadata
    char meta_path[2048];
    snprintf(meta_path, sizeof(meta_path), "%s/databases.meta", g_db_manager.persistence_path);
    
    FILE* fp = fopen(meta_path, "r");
    if (fp) {
        json_error_t error;
        json_t* root = json_loadf(fp, 0, &error);
        fclose(fp);
        
        if (root) {
            json_t* dbs = json_object_get(root, "databases");
            if (json_is_array(dbs)) {
                size_t index;
                json_t* value;
                json_array_foreach(dbs, index, value) {
                    const char* db_name = json_string_value(json_object_get(value, "name"));
                    if (db_name) {
                        // Create or open the database
                        db_error_t err = db_create(db_name);
                        if (err != DB_SUCCESS && err != DB_ERROR_DATABASE_EXISTS) {
                            json_decref(root);
                            return err;
                        }

                        // Open if it was marked as open
                        if (json_boolean_value(json_object_get(value, "is_open"))) {
                            db_open(db_name);
                        }

                        // Recover collections
                        json_t* cols = json_object_get(value, "collections");
                        if (json_is_array(cols)) {
                            size_t col_idx;
                            json_t* col_val;
                            json_array_foreach(cols, col_idx, col_val) {
                                const char* col_name = json_string_value(json_object_get(col_val, "name"));
                                if (col_name) {
                                    db_error_t col_err = db_create_collection(db_name, col_name);
                                    if (col_err != DB_SUCCESS && col_err != DB_ERROR_COLLECTION_EXISTS) {
                                        json_decref(root);
                                        return col_err;
                                    }

                                    // Load collection data if it was open
                                    if (json_boolean_value(json_object_get(col_val, "is_open"))) {
                                        Collection* col = find_collection(find_database(db_name), col_name);
                                        if (col) {
                                            pthread_rwlock_wrlock(&col->lock);
                                            db_error_t load_err = persistence_load(&col->pm);
                                            pthread_rwlock_unlock(&col->lock);
                                            if (load_err != DB_SUCCESS) {
                                                json_decref(root);
                                                return load_err;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            json_decref(root);
        }
    }
    
    // 2. Fallback: Scan directory structure for any missing databases/collections
    DIR* dir = opendir(g_db_manager.persistence_path);
    if (!dir) {
        return DB_SUCCESS; // No persistence directory is not an error
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        // Skip special entries
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // Check for database directories
        char db_path[2048];
        snprintf(db_path, sizeof(db_path), "%s/%s", g_db_manager.persistence_path, entry->d_name);
        
        struct stat st;
        if (stat(db_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            // This is a potential database directory
            const char* db_name = entry->d_name;
            
            // Create database if it doesn't exist
            int exists;
            db_error_t err = db_exists(db_name, &exists);
            if (err != DB_SUCCESS) continue;
            
            if (!exists) {
                err = db_create(db_name);
                if (err != DB_SUCCESS) continue;
            }

            // Open the database
            db_open(db_name);
            Database* db = find_database(db_name);
            if (!db) continue;

            // Scan for collections
            DIR* col_dir = opendir(db_path);
            if (!col_dir) continue;
            
            struct dirent* col_entry;
            while ((col_entry = readdir(col_dir)) != NULL) {
                // Skip special entries
                if (strcmp(col_entry->d_name, ".") == 0 || strcmp(col_entry->d_name, "..") == 0) {
                    continue;
                }

                // Check for collection directories
                char col_path[2048];
                snprintf(col_path, sizeof(col_path), "%s/%s", db_path, col_entry->d_name);
                
                if (stat(col_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                    const char* col_name = col_entry->d_name;
                    
                    // Create collection if it doesn't exist
                    int col_exists;
                    err = db_collection_exists(db_name, col_name, &col_exists);
                    if (err != DB_SUCCESS) continue;
                    
                    if (!col_exists) {
                        err = db_create_collection(db_name, col_name);
                        if (err != DB_SUCCESS) continue;
                    }

                    // Load collection data
                    Collection* col = find_collection(db, col_name);
                    if (col) {
                        pthread_rwlock_wrlock(&col->lock);
                        persistence_load(&col->pm);
                        pthread_rwlock_unlock(&col->lock);
                    }
                }
            }
            closedir(col_dir);
        }
    }
    closedir(dir);
    
    return DB_SUCCESS;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <persistence_path> <port>\n", argv[0]);
        exit(1);
    }
    const char* persistence_path = argv[1];
    int port = atoi(argv[2]);
    if (port <= 0) port = DEFAULT_PORT;

    // Setup signal handlers with proper sigaction
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);

    // Initialize database manager with enhanced error reporting
    printf("Initializing database system...\n");
    db_error_t err = db_manager_init(persistence_path);
    if (err != DB_SUCCESS) {
        fprintf(stderr, "Failed to initialize database manager: %s\n", db_error_string(err));
        exit(1);
    }

    // Auto-recover databases with progress reporting
    printf("Recovering databases from %s...\n", persistence_path);
    err = db_recover_all();
    if (err != DB_SUCCESS) {
        fprintf(stderr, "Warning: Database recovery encountered issues: %s\n", 
                db_error_string(err));
        // Continue with partial recovery
    }

    // Start periodic autosave (every 5 minutes)
    printf("Starting autosave thread...\n");
    err = db_autosave_start(300); // 300 seconds = 5 minutes
    if (err != DB_SUCCESS) {
        fprintf(stderr, "Warning: Failed to start autosave: %s\n", 
                db_error_string(err));
    }

    // Initialize RBAC system
    printf("Initializing RBAC system...\n");
    if (rbac_init(&g_rbac) != 0) {
        fprintf(stderr, "RBAC initialization failed: %s\n", strerror(errno));
        db_autosave_stop();
        db_manager_cleanup();
        exit(1);
    }

    // Load RBAC state if exists
    char rbac_path[1024];
    snprintf(rbac_path, sizeof(rbac_path), "%s/rbac.json", persistence_path);
    if (access(rbac_path, F_OK) == 0) {
        printf("Loading RBAC state from %s...\n", rbac_path);
        if (rbac_load(&g_rbac, rbac_path) != 0) {
            fprintf(stderr, "Warning: Failed to load RBAC state\n");
        }
    } else {
        printf("No existing RBAC state found, starting fresh\n");
    }

    // Create server socket with enhanced error handling
    printf("Starting server on port %d...\n", port);
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        goto cleanup;
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Setsockopt failed");
        goto cleanup;
    }

    // Bind socket
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(port)
    };
    
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        goto cleanup;
    }

    // Listen for connections
    if (listen(server_fd, 10) < 0) {
        perror("Listen failed");
        goto cleanup;
    }

    printf("Server ready and accepting connections\n");
    
    // Main server loop
    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) {
                // Interrupted by signal, likely shutting down
                break;
            }
            perror("Accept failed");
            continue;
        }

        // Handle client in new thread
        pthread_t thread;
        if (pthread_create(&thread, NULL, client_handler, (void*)(intptr_t)client_fd) != 0) {
            perror("Thread creation failed");
            close(client_fd);
            continue;
        }
        pthread_detach(thread);
    }

cleanup:
    // Cleanup sequence
    printf("Server shutting down...\n");
    
    // Stop autosave thread first
    db_autosave_stop();
    
    // Close server socket if open
    if (server_fd >= 0) {
        close(server_fd);
    }

    // Save all data before exiting
    printf("Saving all databases...\n");
    db_error_t save_err = db_save_all();
    if (save_err != DB_SUCCESS) {
        fprintf(stderr, "Warning: Final save failed: %s\n", db_error_string(save_err));
    }

    // Save RBAC state
    printf("Saving RBAC state...\n");
    if (rbac_save(&g_rbac, rbac_path) != 0) {
        fprintf(stderr, "Warning: Failed to save RBAC state\n");
    }

    // Cleanup resources
    printf("Cleaning up resources...\n");
    db_manager_cleanup();
    rbac_cleanup(&g_rbac);

    printf("Server shutdown complete\n");
    return 0;
}