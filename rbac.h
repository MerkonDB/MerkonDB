// rbac.h
#ifndef RBAC_H
#define RBAC_H

#include <stdbool.h>
#include <pthread.h>
#include <jansson.h>

#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 128
#define MAX_ROLE_LEN 32
#define MAX_PERMISSION_LEN 32
#define MAX_USERS 100
#define MAX_ROLES 20
#define MAX_PERMISSIONS 50

typedef enum {
    PERM_NONE = 0,
    PERM_READ = 1 << 0,
    PERM_WRITE = 1 << 1,
    PERM_CREATE = 1 << 2,
    PERM_DELETE = 1 << 3,
    PERM_ADMIN = 1 << 4,
    PERM_ALL = (PERM_READ | PERM_WRITE | PERM_CREATE | PERM_DELETE | PERM_ADMIN)
} Permission;

typedef struct {
    char name[MAX_ROLE_LEN];
    int permissions;
} Role;

typedef struct {
    char username[MAX_USERNAME_LEN];
    char password_hash[MAX_PASSWORD_LEN]; // Store hashed passwords only
    char roles[MAX_ROLES][MAX_ROLE_LEN];
    int role_count;
} User;

typedef struct {
    User users[MAX_USERS];
    Role roles[MAX_ROLES];
    int user_count;
    int role_count;
    pthread_rwlock_t lock;
    bool is_initialized;
} RBACSystem;

// RBAC initialization and management
int rbac_init(RBACSystem* rbac);
void rbac_cleanup(RBACSystem* rbac);

// User management
int rbac_add_user(RBACSystem* rbac, const char* username, const char* password);
int rbac_remove_user(RBACSystem* rbac, const char* username);
int rbac_authenticate_user(RBACSystem* rbac, const char* username, const char* password);

// Role management
int rbac_add_role(RBACSystem* rbac, const char* role_name, int permissions);
int rbac_remove_role(RBACSystem* rbac, const char* role_name);

// Assignment
int rbac_assign_role(RBACSystem* rbac, const char* username, const char* role_name);
int rbac_revoke_role(RBACSystem* rbac, const char* username, const char* role_name);

// Permission checking
bool rbac_has_permission(RBACSystem* rbac, const char* username, int permission);
bool rbac_has_db_permission(RBACSystem* rbac, const char* username, const char* db_name, int permission);

// Persistence
int rbac_save(RBACSystem* rbac, const char* path);
int rbac_load(RBACSystem* rbac, const char* path);

#endif // RBAC_H