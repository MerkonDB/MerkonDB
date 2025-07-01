// server.c
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
#include <signal.h>

// Include original smt_db.c functions
#include "smt_db.c"

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
    char* username = NULL; // Change to char* to hold copied string
    time_t now;
    char timestamp[32];

    // Get current timestamp
    time(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    // Get client IP address
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername(client_fd, (struct sockaddr*)&addr, &addr_len) == 0) {
        client_ip = inet_ntoa(addr.sin_addr);
    }
    
    printf("[%s] [CONNECT] New connection from %s (FD: %d)\n", timestamp, client_ip, client_fd);

    // Authentication phase
    if (read_message(client_fd, &message) != 0) {
        printf("[%s] [ERROR] Failed to read auth message from %s (FD: %d)\n", 
               timestamp, client_ip, client_fd);
        close(client_fd);
        return NULL;
    }

    printf("[%s] [DEBUG] Auth message from %s: %.*s\n", 
           timestamp, client_ip, 
           (int)(message ? strnlen(message, 256) : 0), 
           message ? message : "NULL");

    json_t* auth = json_loads(message, 0, &error);
    free(message);
    message = NULL;

    if (!auth) {
        printf("[%s] [ERROR] Invalid JSON from %s: %s (line %d, col %d)\n", 
               timestamp, client_ip, error.text, error.line, error.column);
        
        json_t* response = json_object();
        json_object_set_new(response, "status", json_string("error"));
        json_object_set_new(response, "error_message", json_string("Invalid authentication JSON"));
        
        char* resp_str = json_dumps(response, JSON_COMPACT);
        if (resp_str) {
            write_message(client_fd, resp_str);
            free(resp_str);
        } else {
            printf("[%s] [ERROR] Failed to serialize error response\n", timestamp);
        }
        json_decref(response);
        close(client_fd);
        return NULL;
    }

    json_t* auth_obj = json_object_get(auth, "auth");
    if (!auth_obj || !json_is_object(auth_obj)) {
        printf("[%s] [ERROR] Missing or invalid auth object from %s\n", timestamp, client_ip);
        
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
        printf("[%s] [ERROR] Missing credentials from %s\n", timestamp, client_ip);
        
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

    // Create a copy of the username
    username = strdup(temp_username);
    if (!username) {
        printf("[%s] [ERROR] Failed to allocate memory for username\n", timestamp);
        
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
        printf("[%s] [AUTH] Failed for user '%s' from %s (code: %d)\n", 
               timestamp, username, client_ip, auth_result);
        
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

    // Main message processing loop
    while (1) {
        // Get new timestamp for each operation
        time(&now);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

        int read_result = read_message(client_fd, &message);
        if (read_result != 0) {
            printf("[%s] [DISCONNECT] Client %s (user: %s) closed connection\n", 
                   timestamp, client_ip, username ? username : "unknown");
            break;
        }

        printf("[%s] [DEBUG] Message from %s (user: %s): %.*s\n", 
               timestamp, client_ip, username ? username : "unknown",
               (int)(message ? strnlen(message, 256) : 0), 
               message ? message : "NULL");

        json_t* root = json_loads(message, 0, &error);
        free(message);
        message = NULL;

        if (!root) {
            printf("[%s] [ERROR] Invalid JSON from %s (user: %s): %s\n", 
                   timestamp, client_ip, username ? username : "unknown", error.text);
            
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
            printf("[%s] [ERROR] Missing operation from %s (user: %s)\n", 
                   timestamp, client_ip, username ? username : "unknown");
            
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

        printf("[%s] [OP] %s from %s (user: %s)\n", 
               timestamp, operation, client_ip, username ? username : "unknown");

        // Permission checking
        int required_perm = PERM_NONE;
        if (strcmp(operation, "rbac_add_user") == 0 || 
            strcmp(operation, "rbac_add_role") == 0 ||
            strcmp(operation, "rbac_assign_role") == 0 ||
            strcmp(operation, "rbac_remove_user") == 0 ||
            strcmp(operation, "rbac_remove_role") == 0 ||
            strcmp(operation, "rbac_revoke_role") == 0) {
            required_perm = PERM_ADMIN;
        } else if (strstr(operation, "find") || strstr(operation, "list") || strstr(operation, "get")) {
            required_perm = PERM_READ;
        } else if (strstr(operation, "insert") || strstr(operation, "update") || 
                   strstr(operation, "create") || strstr(operation, "open")) {
            required_perm = PERM_WRITE;
        } else if (strstr(operation, "delete") || strstr(operation, "drop") || 
                   strstr(operation, "close")) {
            required_perm = PERM_DELETE;
        }

        const char* db_name = json_string_value(json_object_get(params, "db_name"));
        if (required_perm != PERM_NONE && required_perm != PERM_ADMIN && db_name) {
            if (!rbac_has_db_permission(&g_rbac, username, db_name, required_perm)) {
                printf("[%s] [AUTH] Denied %s on %s for %s\n", 
                       timestamp, operation, db_name, username ? username : "unknown");
                
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

        // RBAC operations
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
        } else {
            json_object_set_new(response, "status", json_string("error"));
            json_object_set_new(response, "error_message", json_string("Unknown operation"));
        }

time_t now;
char timestamp[32];
time(&now);
strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

printf("[%s] [DEBUG] Preparing response for operation '%s'\n", timestamp, operation);
char* resp_str = json_dumps(response, JSON_COMPACT);
if (resp_str) {
    printf("[%s] [DEBUG] Response to %s: %.*s\n", 
           timestamp, client_ip,
           (int)strnlen(resp_str, 256), resp_str);
    if (write_message(client_fd, resp_str) != 0) {
        printf("[%s] [ERROR] Failed to send response to %s for operation '%s'\n", 
               timestamp, client_ip, operation);
        free(resp_str);
        json_decref(response);
        json_decref(root);
        break;
    }
    free(resp_str);
} else {
    printf("[%s] [ERROR] Failed to serialize response for operation '%s'\n", timestamp, operation);
    const char* fallback = "{\"status\":\"error\",\"error_message\":\"Server failed to serialize response\"}";
    printf("[%s] [DEBUG] Fallback response to %s: %s\n", timestamp, client_ip, fallback);
    if (write_message(client_fd, fallback) != 0) {
        printf("[%s] [ERROR] Failed to send fallback response to %s for operation '%s'\n", 
               timestamp, client_ip, operation);
        json_decref(response);
        json_decref(root);
        break;
    }
}

// Persist RBAC state after successful RBAC operations
if (strncmp(operation, "rbac_", 5) == 0 && strcmp(json_string_value(json_object_get(response, "status")), "success") == 0) {
    printf("[%s] [DEBUG] Saving RBAC state after %s\n", timestamp, operation);
    char rbac_path[1024];
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

    // Cleanup
    if (message) {
        free(message);
    }
    
    printf("[%s] [DISCONNECT] Closing connection for %s (user: %s)\n", 
           timestamp, client_ip, username ? username : "unknown");
    free(username); // Free the copied username
    close(client_fd);
    return NULL;
}
static void signal_handler(int sig) {
    if (server_fd >= 0) {
        close(server_fd);
    }

    // Save RBAC data
    char rbac_path[1024];
    snprintf(rbac_path, sizeof(rbac_path), "%s/rbac.json", g_db_manager.persistence_path);
    rbac_save(&g_rbac, rbac_path);

    db_manager_cleanup();
    rbac_cleanup(&g_rbac);
    exit(0);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <persistence_path> <port>\n", argv[0]);
        exit(1);
    }
    const char* persistence_path = argv[1];
    int port = atoi(argv[2]);
    if (port <= 0) port = DEFAULT_PORT;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    db_error_t err = db_manager_init(persistence_path);
    if (err != DB_SUCCESS) {
        fprintf(stderr, "Failed to initialize database manager: %s\n", db_error_string(err));
        exit(1);
    }
    err = db_load_all();
    if (err != DB_SUCCESS) {
        fprintf(stderr, "Failed to load databases: %s\n", db_error_string(err));
        db_manager_cleanup();
        exit(1);
    }

    // Initialize RBAC system
    if (rbac_init(&g_rbac) != 0) {
        fprintf(stderr, "RBAC initialization failed with errno: %d (%s)\n", errno, strerror(errno));
        db_manager_cleanup();
        exit(1);
    }

    // Load RBAC data if exists
    char rbac_path[1024];
    snprintf(rbac_path, sizeof(rbac_path), "%s/rbac.json", persistence_path);
    rbac_load(&g_rbac, rbac_path);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        db_manager_cleanup();
        rbac_cleanup(&g_rbac);
        exit(1);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY, .sin_port = htons(port) };
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        db_manager_cleanup();
        rbac_cleanup(&g_rbac);
        exit(1);
    }

    if (listen(server_fd, 10) < 0) {
        perror("Listen failed");
        close(server_fd);
        db_manager_cleanup();
        rbac_cleanup(&g_rbac);
        exit(1);
    }

    printf("Server running on port %d\n", port);
    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            perror("Accept failed");
            continue;
        }
        pthread_t thread;
        if (pthread_create(&thread, NULL, client_handler, (void*)(intptr_t)client_fd) != 0) {
            perror("Thread creation failed");
            close(client_fd);
            continue;
        }
        pthread_detach(thread);
    }

    close(server_fd);
    db_manager_cleanup();
    rbac_cleanup(&g_rbac);
    return 0;
}