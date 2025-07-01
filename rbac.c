// rbac.c - Fixed version
#include "rbac.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

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
    time_t now;
    char timestamp[32];
    time(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    if (!rbac) {
        printf("[%s] [ERROR] rbac_init: NULL rbac pointer\n", timestamp);
        return -1;
    }

    printf("[%s] [DEBUG] rbac_init: Initializing RBAC system\n", timestamp);
    memset(rbac, 0, sizeof(RBACSystem));
    
    int ret;
    pthread_rwlockattr_t attr;
    pthread_rwlockattr_init(&attr);
    pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
    
    if ((ret = pthread_rwlock_init(&rbac->lock, &attr)) != 0) {
        printf("[%s] [ERROR] rbac_init: pthread_rwlock_init failed: %s\n", timestamp, strerror(ret));
        pthread_rwlockattr_destroy(&attr);
        return -1;
    }
    pthread_rwlockattr_destroy(&attr);

    rbac->is_initialized = true;
    printf("[%s] [DEBUG] rbac_init: Lock initialized, is_initialized set to true\n", timestamp);

    // Add admin role without using the lock (we're in init, no contention possible)
    if (rbac->role_count < MAX_ROLES) {
        Role* role = &rbac->roles[rbac->role_count++];
        strncpy(role->name, "admin", MAX_ROLE_LEN - 1);
        role->name[MAX_ROLE_LEN - 1] = '\0';
        role->permissions = PERM_ALL;
        printf("[%s] [DEBUG] rbac_init: Admin role added successfully\n", timestamp);
    } else {
        printf("[%s] [ERROR] rbac_init: Failed to add admin role - no space\n", timestamp);
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
    time_t now;
    char timestamp[32];
    time(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    if (!rbac || !rbac->is_initialized || !username || !password) {
        printf("[%s] [ERROR] rbac_add_user: Invalid input parameters\n", timestamp);
        return -1;
    }

    printf("[%s] [DEBUG] rbac_add_user: Adding user '%s'\n", timestamp, username);

    if (strlen(username) >= MAX_USERNAME_LEN || strlen(password) >= MAX_PASSWORD_LEN) {
        printf("[%s] [ERROR] rbac_add_user: Username or password too long\n", timestamp);
        return -1;
    }

    // Use a more robust timeout mechanism
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        // Fallback to CLOCK_REALTIME if MONOTONIC is not available
        if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
            printf("[%s] [ERROR] rbac_add_user: Failed to get current time: %s\n", 
                   timestamp, strerror(errno));
            return -1;
        }
    }
    ts.tv_sec += 10; // Increased timeout to 10 seconds

    printf("[%s] [DEBUG] rbac_add_user: Attempting to acquire write lock\n", timestamp);
    int ret = pthread_rwlock_timedwrlock(&rbac->lock, &ts);
    if (ret != 0) {
        printf("[%s] [ERROR] rbac_add_user: Failed to acquire write lock for user '%s': %s (errno: %d)\n", 
               timestamp, username, strerror(ret), ret);
        
        // Try non-blocking approach as fallback
        ret = pthread_rwlock_trywrlock(&rbac->lock);
        if (ret != 0) {
            printf("[%s] [ERROR] rbac_add_user: Non-blocking lock also failed: %s\n", 
                   timestamp, strerror(ret));
            return -1;
        }
        printf("[%s] [DEBUG] rbac_add_user: Acquired lock via non-blocking fallback\n", timestamp);
    } else {
        printf("[%s] [DEBUG] rbac_add_user: Write lock acquired successfully\n", timestamp);
    }

    // Check limits
    if (rbac->user_count >= MAX_USERS) {
        printf("[%s] [ERROR] rbac_add_user: Maximum user limit reached\n", timestamp);
        pthread_rwlock_unlock(&rbac->lock);
        return -1;
    }

    // Check for existing user
    for (int i = 0; i < rbac->user_count; i++) {
        if (strcmp(rbac->users[i].username, username) == 0) {
            printf("[%s] [ERROR] rbac_add_user: User '%s' already exists\n", timestamp, username);
            pthread_rwlock_unlock(&rbac->lock);
            return -1;
        }
    }

    // Add the user
    printf("[%s] [DEBUG] rbac_add_user: Adding new user at index %d\n", timestamp, rbac->user_count);
    User* user = &rbac->users[rbac->user_count++];
    strncpy(user->username, username, MAX_USERNAME_LEN - 1);
    user->username[MAX_USERNAME_LEN - 1] = '\0';
    printf("[%s] [DEBUG] rbac_add_user: Username copied: %s\n", timestamp, user->username);
    
    hash_password(password, user->password_hash);
    printf("[%s] [DEBUG] rbac_add_user: Password hashed\n", timestamp);
    user->role_count = 0;

    printf("[%s] [DEBUG] rbac_add_user: Releasing lock\n", timestamp);
    pthread_rwlock_unlock(&rbac->lock);
    printf("[%s] [DEBUG] rbac_add_user: User '%s' added successfully\n", timestamp, username);
    return 0;
}

int rbac_remove_user(RBACSystem* rbac, const char* username) {
    if (!rbac || !rbac->is_initialized || !username) return -1;

    int ret = pthread_rwlock_trywrlock(&rbac->lock);
    if (ret != 0) {
        // If try fails, use timeout
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;
        ret = pthread_rwlock_timedwrlock(&rbac->lock, &ts);
        if (ret != 0) return -1;
    }

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

    int ret = pthread_rwlock_tryrdlock(&rbac->lock);
    if (ret != 0) {
        // If try fails, use timeout
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;
        ret = pthread_rwlock_timedrdlock(&rbac->lock, &ts);
        if (ret != 0) return -1;
    }

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

    int ret = pthread_rwlock_trywrlock(&rbac->lock);
    if (ret != 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;
        ret = pthread_rwlock_timedwrlock(&rbac->lock, &ts);
        if (ret != 0) return -1;
    }

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

    int ret = pthread_rwlock_trywrlock(&rbac->lock);
    if (ret != 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;
        ret = pthread_rwlock_timedwrlock(&rbac->lock, &ts);
        if (ret != 0) return -1;
    }

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

    int ret = pthread_rwlock_trywrlock(&rbac->lock);
    if (ret != 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;
        ret = pthread_rwlock_timedwrlock(&rbac->lock, &ts);
        if (ret != 0) return -1;
    }

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

    int ret = pthread_rwlock_trywrlock(&rbac->lock);
    if (ret != 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;
        ret = pthread_rwlock_timedwrlock(&rbac->lock, &ts);
        if (ret != 0) return -1;
    }

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

    int ret = pthread_rwlock_tryrdlock(&rbac->lock);
    if (ret != 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;
        ret = pthread_rwlock_timedrdlock(&rbac->lock, &ts);
        if (ret != 0) return false;
    }

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
    time_t now;
    char timestamp[32];
    time(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    if (!rbac || !rbac->is_initialized || !path) {
        printf("[%s] [ERROR] rbac_save: Invalid input parameters\n", timestamp);
        return -1;
    }

    printf("[%s] [DEBUG] rbac_save: Attempting to acquire write lock for saving to %s\n", timestamp, path);
    int ret = pthread_rwlock_trywrlock(&rbac->lock);
    if (ret != 0) {
        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
            printf("[%s] [ERROR] rbac_save: Failed to get current time: %s\n", timestamp, strerror(errno));
            return -1;
        }
        ts.tv_sec += 5;
        ret = pthread_rwlock_timedwrlock(&rbac->lock, &ts);
        if (ret != 0) {
            printf("[%s] [ERROR] rbac_save: Failed to acquire write lock: %s\n", timestamp, strerror(ret));
            return -1;
        }
    }
    printf("[%s] [DEBUG] rbac_save: Write lock acquired\n", timestamp);

    json_t* root = json_object();
    if (!root) {
        printf("[%s] [ERROR] rbac_save: Failed to create JSON object\n", timestamp);
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
        printf("[%s] [ERROR] rbac_save: Failed to serialize JSON\n", timestamp);
        pthread_rwlock_unlock(&rbac->lock);
        return -1;
    }

    // Write to temporary file first
    char temp_path[2048];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

    int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) {
        printf("[%s] [ERROR] rbac_save: Failed to open temp file %s: %s\n", timestamp, temp_path, strerror(errno));
        free(json_str);
        pthread_rwlock_unlock(&rbac->lock);
        return -1;
    }

    ssize_t written = write(fd, json_str, strlen(json_str));
    free(json_str);
    close(fd);

    if (written == -1) {
        printf("[%s] [ERROR] rbac_save: Failed to write to temp file %s: %s\n", timestamp, temp_path, strerror(errno));
        unlink(temp_path);
        pthread_rwlock_unlock(&rbac->lock);
        return -1;
    }

    // Atomic rename
    if (rename(temp_path, path) == -1) {
        printf("[%s] [ERROR] rbac_save: Failed to rename %s to %s: %s\n", timestamp, temp_path, path, strerror(errno));
        unlink(temp_path);
        pthread_rwlock_unlock(&rbac->lock);
        return -1;
    }

    printf("[%s] [DEBUG] rbac_save: Successfully saved RBAC state to %s\n", timestamp, path);
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

    int ret = pthread_rwlock_trywrlock(&rbac->lock);
    if (ret != 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;
        ret = pthread_rwlock_timedwrlock(&rbac->lock, &ts);
        if (ret != 0) {
            json_decref(root);
            return -1;
        }
    }

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
                Role* new_role = &rbac->roles[rbac->role_count++];
                strncpy(new_role->name, name, MAX_ROLE_LEN - 1);
                new_role->name[MAX_ROLE_LEN - 1] = '\0';
                new_role->permissions = permissions;
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