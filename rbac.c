// rbac.c
#include "rbac.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static void hash_password(const char* password, char* output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Final(hash, &sha256);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[SHA256_DIGEST_LENGTH * 2] = '\0';
}

int rbac_init(RBACSystem* rbac) {
    if (!rbac) return -1;

    memset(rbac, 0, sizeof(RBACSystem));
    
    int ret;
    pthread_rwlockattr_t attr;
    pthread_rwlockattr_init(&attr);
    pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
    
    if ((ret = pthread_rwlock_init(&rbac->lock, &attr)) != 0) {
        fprintf(stderr, "pthread_rwlock_init failed: %s\n", strerror(ret));
        pthread_rwlockattr_destroy(&attr);
        return -1;
    }
    pthread_rwlockattr_destroy(&attr);

    rbac->is_initialized = true; // Move this before rbac_add_role

    // Add default admin role
    if (rbac_add_role(rbac, "admin", PERM_ALL) != 0) {
        pthread_rwlock_destroy(&rbac->lock);
        return -1;
    }

    return 0;
}

void rbac_cleanup(RBACSystem* rbac) {
    if (!rbac || !rbac->is_initialized) return;
    pthread_rwlock_destroy(&rbac->lock);
    memset(rbac, 0, sizeof(RBACSystem));
}

int rbac_add_user(RBACSystem* rbac, const char* username, const char* password) {
    if (!rbac || !rbac->is_initialized || !username || !password) return -1;
    if (strlen(username) >= MAX_USERNAME_LEN || strlen(password) >= MAX_PASSWORD_LEN) return -1;

    pthread_rwlock_wrlock(&rbac->lock);

    if (rbac->user_count >= MAX_USERS) {
        pthread_rwlock_unlock(&rbac->lock);
        return -1;
    }

    // Check if user exists
    for (int i = 0; i < rbac->user_count; i++) {
        if (strcmp(rbac->users[i].username, username) == 0) {
            pthread_rwlock_unlock(&rbac->lock);
            return -1;
        }
    }

    // Add new user
    User* user = &rbac->users[rbac->user_count++];
    strncpy(user->username, username, MAX_USERNAME_LEN - 1);
    user->username[MAX_USERNAME_LEN - 1] = '\0';
    hash_password(password, user->password_hash);
    user->role_count = 0;

    pthread_rwlock_unlock(&rbac->lock);
    return 0;
}

int rbac_remove_user(RBACSystem* rbac, const char* username) {
    if (!rbac || !rbac->is_initialized || !username) return -1;

    pthread_rwlock_wrlock(&rbac->lock);

    for (int i = 0; i < rbac->user_count; i++) {
        if (strcmp(rbac->users[i].username, username) == 0) {
            // Shift remaining users
            for (int j = i; j < rbac->user_count - 1; j++) {
                rbac->users[j] = rbac->users[j + 1];
            }
            rbac->user_count--;
            pthread_rwlock_unlock(&rbac->lock);
            return 0;
        }
    }

    pthread_rwlock_unlock(&rbac->lock);
    return -1;
}

int rbac_authenticate_user(RBACSystem* rbac, const char* username, const char* password) {
    if (!rbac || !rbac->is_initialized || !username || !password) return -1;

    pthread_rwlock_rdlock(&rbac->lock);

    char hashed_password[MAX_PASSWORD_LEN];
    hash_password(password, hashed_password);

    for (int i = 0; i < rbac->user_count; i++) {
        if (strcmp(rbac->users[i].username, username) == 0) {
            if (strcmp(rbac->users[i].password_hash, hashed_password) == 0) {
                pthread_rwlock_unlock(&rbac->lock);
                return 0; // Success
            }
            break;
        }
    }

    pthread_rwlock_unlock(&rbac->lock);
    return -1; // Authentication failed
}

int rbac_add_role(RBACSystem* rbac, const char* role_name, int permissions) {
    if (!rbac || !rbac->is_initialized || !role_name) return -1;
    if (strlen(role_name) >= MAX_ROLE_LEN) return -1;

    pthread_rwlock_wrlock(&rbac->lock);

    if (rbac->role_count >= MAX_ROLES) {
        pthread_rwlock_unlock(&rbac->lock);
        return -1;
    }

    // Check if role exists
    for (int i = 0; i < rbac->role_count; i++) {
        if (strcmp(rbac->roles[i].name, role_name) == 0) {
            pthread_rwlock_unlock(&rbac->lock);
            return -1;
        }
    }

    // Add new role
    Role* role = &rbac->roles[rbac->role_count++];
    strncpy(role->name, role_name, MAX_ROLE_LEN - 1);
    role->name[MAX_ROLE_LEN - 1] = '\0';
    role->permissions = permissions;

    pthread_rwlock_unlock(&rbac->lock);
    return 0;
}

int rbac_remove_role(RBACSystem* rbac, const char* role_name) {
    if (!rbac || !rbac->is_initialized || !role_name) return -1;

    pthread_rwlock_wrlock(&rbac->lock);

    for (int i = 0; i < rbac->role_count; i++) {
        if (strcmp(rbac->roles[i].name, role_name) == 0) {
            // Remove role from all users
            for (int j = 0; j < rbac->user_count; j++) {
                for (int k = 0; k < rbac->users[j].role_count; k++) {
                    if (strcmp(rbac->users[j].roles[k], role_name) == 0) {
                        // Shift remaining roles
                        for (int m = k; m < rbac->users[j].role_count - 1; m++) {
                            strcpy(rbac->users[j].roles[m], rbac->users[j].roles[m + 1]);
                        }
                        rbac->users[j].role_count--;
                    }
                }
            }
            // Shift remaining roles
            for (int j = i; j < rbac->role_count - 1; j++) {
                rbac->roles[j] = rbac->roles[j + 1];
            }
            rbac->role_count--;
            pthread_rwlock_unlock(&rbac->lock);
            return 0;
        }
    }

    pthread_rwlock_unlock(&rbac->lock);
    return -1;
}

int rbac_assign_role(RBACSystem* rbac, const char* username, const char* role_name) {
    if (!rbac || !rbac->is_initialized || !username || !role_name) return -1;

    pthread_rwlock_wrlock(&rbac->lock);

    // Find user
    User* user = NULL;
    for (int i = 0; i < rbac->user_count; i++) {
        if (strcmp(rbac->users[i].username, username) == 0) {
            user = &rbac->users[i];
            break;
        }
    }
    if (!user) {
        pthread_rwlock_unlock(&rbac->lock);
        return -1;
    }

    // Check if role exists
    bool role_exists = false;
    for (int i = 0; i < rbac->role_count; i++) {
        if (strcmp(rbac->roles[i].name, role_name) == 0) {
            role_exists = true;
            break;
        }
    }
    if (!role_exists) {
        pthread_rwlock_unlock(&rbac->lock);
        return -1;
    }

    // Check if user already has role
    for (int i = 0; i < user->role_count; i++) {
        if (strcmp(user->roles[i], role_name) == 0) {
            pthread_rwlock_unlock(&rbac->lock);
            return 0; // Role already assigned
        }
    }

    if (user->role_count >= MAX_ROLES) {
        pthread_rwlock_unlock(&rbac->lock);
        return -1;
    }

    // Assign role
    strncpy(user->roles[user->role_count++], role_name, MAX_ROLE_LEN - 1);
    user->roles[user->role_count - 1][MAX_ROLE_LEN - 1] = '\0';

    pthread_rwlock_unlock(&rbac->lock);
    return 0;
}

int rbac_revoke_role(RBACSystem* rbac, const char* username, const char* role_name) {
    if (!rbac || !rbac->is_initialized || !username || !role_name) return -1;

    pthread_rwlock_wrlock(&rbac->lock);

    // Find user
    User* user = NULL;
    for (int i = 0; i < rbac->user_count; i++) {
        if (strcmp(rbac->users[i].username, username) == 0) {
            user = &rbac->users[i];
            break;
        }
    }
    if (!user) {
        pthread_rwlock_unlock(&rbac->lock);
        return -1;
    }

    // Find and remove role
    for (int i = 0; i < user->role_count; i++) {
        if (strcmp(user->roles[i], role_name) == 0) {
            // Shift remaining roles
            for (int j = i; j < user->role_count - 1; j++) {
                strcpy(user->roles[j], user->roles[j + 1]);
            }
            user->role_count--;
            pthread_rwlock_unlock(&rbac->lock);
            return 0;
        }
    }

    pthread_rwlock_unlock(&rbac->lock);
    return -1;
}

bool rbac_has_permission(RBACSystem* rbac, const char* username, int permission) {
    if (!rbac || !rbac->is_initialized || !username) return false;

    pthread_rwlock_rdlock(&rbac->lock);

    // Find user
    User* user = NULL;
    for (int i = 0; i < rbac->user_count; i++) {
        if (strcmp(rbac->users[i].username, username) == 0) {
            user = &rbac->users[i];
            break;
        }
    }
    if (!user) {
        pthread_rwlock_unlock(&rbac->lock);
        return false;
    }

    // Check roles
    for (int i = 0; i < user->role_count; i++) {
        for (int j = 0; j < rbac->role_count; j++) {
            if (strcmp(user->roles[i], rbac->roles[j].name) == 0) {
                if (rbac->roles[j].permissions & permission) {
                    pthread_rwlock_unlock(&rbac->lock);
                    return true;
                }
                break;
            }
        }
    }

    pthread_rwlock_unlock(&rbac->lock);
    return false;
}

bool rbac_has_db_permission(RBACSystem* rbac, const char* username, const char* db_name, int permission) {
    // For simplicity, we're using global permissions. In a more complex system,
    // this could check database-specific permissions
    return rbac_has_permission(rbac, username, permission);
}

int rbac_save(RBACSystem* rbac, const char* path) {
    if (!rbac || !rbac->is_initialized || !path) return -1;

    pthread_rwlock_rdlock(&rbac->lock);

    json_t* root = json_object();
    if (!root) {
        pthread_rwlock_unlock(&rbac->lock);
        return -1;
    }

    // Serialize roles
    json_t* roles = json_array();
    for (int i = 0; i < rbac->role_count; i++) {
        json_t* role = json_object();
        json_object_set_new(role, "name", json_string(rbac->roles[i].name));
        json_object_set_new(role, "permissions", json_integer(rbac->roles[i].permissions));
        json_array_append_new(roles, role);
    }
    json_object_set_new(root, "roles", roles);

    // Serialize users
    json_t* users = json_array();
    for (int i = 0; i < rbac->user_count; i++) {
        json_t* user = json_object();
        json_object_set_new(user, "username", json_string(rbac->users[i].username));
        json_object_set_new(user, "password_hash", json_string(rbac->users[i].password_hash));
        json_t* user_roles = json_array();
        for (int j = 0; j < rbac->users[i].role_count; j++) {
            json_array_append_new(user_roles, json_string(rbac->users[i].roles[j]));
        }
        json_object_set_new(user, "roles", user_roles);
        json_array_append_new(users, user);
    }
    json_object_set_new(root, "users", users);

    char* json_str = json_dumps(root, JSON_COMPACT);
    json_decref(root);

    if (!json_str) {
        pthread_rwlock_unlock(&rbac->lock);
        return -1;
    }

    // Write to temporary file first
    char temp_path[2048];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

    int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) {
        free(json_str);
        pthread_rwlock_unlock(&rbac->lock);
        return -1;
    }

    ssize_t written = write(fd, json_str, strlen(json_str));
    free(json_str);
    close(fd);

    if (written == -1) {
        unlink(temp_path);
        pthread_rwlock_unlock(&rbac->lock);
        return -1;
    }

    // Atomic rename
    if (rename(temp_path, path) == -1) {
        unlink(temp_path);
        pthread_rwlock_unlock(&rbac->lock);
        return -1;
    }

    pthread_rwlock_unlock(&rbac->lock);
    return 0;
}

int rbac_load(RBACSystem* rbac, const char* path) {
    if (!rbac || !rbac->is_initialized || !path) return -1;

    int fd = open(path, O_RDONLY);
    if (fd == -1) return -1;

    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
        return -1;
    }

    char* buffer = malloc(st.st_size + 1);
    if (!buffer) {
        close(fd);
        return -1;
    }

    if (read(fd, buffer, st.st_size) != st.st_size) {
        free(buffer);
        close(fd);
        return -1;
    }
    buffer[st.st_size] = '\0';
    close(fd);

    json_error_t error;
    json_t* root = json_loads(buffer, 0, &error);
    free(buffer);

    if (!root) return -1;

    pthread_rwlock_wrlock(&rbac->lock);

    // Clear existing data
    rbac->user_count = 0;
    rbac->role_count = 0;

    // Load roles
    json_t* roles = json_object_get(root, "roles");
    if (roles && json_is_array(roles)) {
        size_t index;
        json_t* role;
        json_array_foreach(roles, index, role) {
            const char* name = json_string_value(json_object_get(role, "name"));
            int permissions = json_integer_value(json_object_get(role, "permissions"));
            if (name && rbac->role_count < MAX_ROLES) {
                rbac_add_role(rbac, name, permissions);
            }
        }
    }

    // Load users
    json_t* users = json_object_get(root, "users");
    if (users && json_is_array(users)) {
        size_t index;
        json_t* user;
        json_array_foreach(users, index, user) {
            const char* username = json_string_value(json_object_get(user, "username"));
            const char* password_hash = json_string_value(json_object_get(user, "password_hash"));
            if (username && password_hash && rbac->user_count < MAX_USERS) {
                User* new_user = &rbac->users[rbac->user_count++];
                strncpy(new_user->username, username, MAX_USERNAME_LEN - 1);
                new_user->username[MAX_USERNAME_LEN - 1] = '\0';
                strncpy(new_user->password_hash, password_hash, MAX_PASSWORD_LEN - 1);
                new_user->password_hash[MAX_PASSWORD_LEN - 1] = '\0';
                new_user->role_count = 0;

                json_t* user_roles = json_object_get(user, "roles");
                if (user_roles && json_is_array(user_roles)) {
                    size_t role_index;
                    json_t* role_name;
                    json_array_foreach(user_roles, role_index, role_name) {
                        if (new_user->role_count < MAX_ROLES) {
                            const char* role_str = json_string_value(role_name);
                            if (role_str) {
                                strncpy(new_user->roles[new_user->role_count++], 
                                        role_str, MAX_ROLE_LEN - 1);
                                new_user->roles[new_user->role_count - 1][MAX_ROLE_LEN - 1] = '\0';
                            }
                        }
                    }
                }
            }
        }
    }

    json_decref(root);
    pthread_rwlock_unlock(&rbac->lock);
    return 0;
}