#include "smt_db.h"
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define MAX_INPUT 256
#define VERSION "1.0.0"

// UI Colors
#define COLOR_RESET   "\x1b[0m"
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_WHITE   "\x1b[37m"
#define COLOR_GRAY    "\x1b[90m"

// Function prototypes
void print_header();
void print_menu();
void print_status(const char* message, int is_error);
void print_visual_db();
int get_input(char* buffer, size_t size);
void print_proof_details(const MembershipProof* proof);
void print_hex_hash(const unsigned char* hash, size_t length);
void print_verification_details(int valid);

// Database operations
void create_database_ui();
void create_collection_ui();
void insert_data_ui();
void find_data_ui();
void generate_proof_ui();
void verify_proof_ui();
void show_stats_ui();

int main() {
    // Initialize the database manager
    if (db_manager_init("./smt_db") != DB_SUCCESS) {
        fprintf(stderr, "Failed to initialize database manager\n");
        return 1;
    }

    char input[MAX_INPUT];
    int running = 1;

    while (running) {
        print_header();
        print_menu();

        if (get_input(input, MAX_INPUT) != 0) {
            print_status("Invalid input", 1);
            continue;
        }

        if (strcmp(input, "1") == 0) {
            create_database_ui();
        } else if (strcmp(input, "2") == 0) {
            create_collection_ui();
        } else if (strcmp(input, "3") == 0) {
            insert_data_ui();
        } else if (strcmp(input, "4") == 0) {
            find_data_ui();
        } else if (strcmp(input, "5") == 0) {
            generate_proof_ui();
        } else if (strcmp(input, "6") == 0) {
            verify_proof_ui();
        } else if (strcmp(input, "7") == 0) {
            show_stats_ui();
        } else if (strcmp(input, "8") == 0) {
            db_error_t result = db_save_all();
            if (result == DB_SUCCESS) {
                print_status("All databases saved successfully", 0);
            } else {
                char error_msg[100];
                snprintf(error_msg, sizeof(error_msg), "Failed to save databases: %s", 
                        db_error_string(result));
                print_status(error_msg, 1);
            }
        } else if (strcmp(input, "9") == 0) {
            print_visual_db();
        } else if (strcmp(input, "10") == 0) {
            running = 0;
        } else {
            print_status("Invalid option selected", 1);
        }
    }

    db_manager_cleanup();
    return 0;
}

void print_header() {
    printf(COLOR_CYAN "\n=== Partitioned Merkle Array Tree Database System ===\n");
    printf(COLOR_YELLOW "Version: %s\n\n" COLOR_RESET, VERSION);
}

void print_menu() {
    printf(COLOR_WHITE "Main Menu:\n");
    printf(" 1. Create Database\n");
    printf(" 2. Create Collection\n");
    printf(" 3. Insert Data\n");
    printf(" 4. Find Data\n");
    printf(" 5. Generate Proof\n");
    printf(" 6. Verify Proof\n");
    printf(" 7. Show Statistics\n");
    printf(" 8. Save All Databases\n");
    printf(" 9. View Database Structure\n");
    printf(" 10. Exit\n\n");
    printf("Enter your choice: " COLOR_RESET);
}

void print_status(const char* message, int is_error) {
    printf("\n");
    if (is_error) {
        printf(COLOR_RED "[ERROR] %s" COLOR_RESET, message);
    } else {
        printf(COLOR_GREEN "[SUCCESS] %s" COLOR_RESET, message);
    }
}

void print_visual_db() {
    printf(COLOR_CYAN "=== Database Structure ===\n\n" COLOR_RESET);
    
    char** db_names = NULL;
    size_t db_count = 0;
    
    db_error_t result = db_list(&db_names, &db_count);
    if (result != DB_SUCCESS || db_count == 0) {
        print_status("No databases found or error accessing databases", 1);
        if (db_names) {
            for (size_t i = 0; i < db_count; i++) {
                free(db_names[i]);
            }
            free(db_names);
        }
        return;
    }

    printf(COLOR_YELLOW "SMT Database\n" COLOR_RESET);
    for (size_t i = 0; i < db_count; i++) {
        printf("├── " COLOR_BLUE "%s" COLOR_RESET "\n", db_names[i]);
        
        char** col_names = NULL;
        size_t col_count = 0;
        result = db_list_collections(db_names[i], &col_names, &col_count);
        
        if (result == DB_SUCCESS && col_count > 0) {
            for (size_t j = 0; j < col_count; j++) {
                printf("│   ├── " COLOR_MAGENTA "%s" COLOR_RESET "\n", col_names[j]);
                
                // Note: db_find_all needs proper implementation in smt_db.c
                char** keys = NULL;
                char** values = NULL;
                size_t record_count = 0;
                result = db_find_all(db_names[i], col_names[j], &keys, &values, &record_count);
                
                if (result == DB_SUCCESS && record_count > 0) {
                    for (size_t k = 0; k < record_count; k++) {
                        printf("│   │   %s %s: %s\n", 
                               (k == record_count - 1 && j == col_count - 1 && i == db_count - 1) ? "└──" : "├──",
                               keys[k], values[k] ? values[k] : "NULL");
                        free(keys[k]);
                        if (values[k]) free(values[k]);
                    }
                    free(keys);
                    free(values);
                } else {
                    printf("│   │   └── " COLOR_GRAY "(empty)" COLOR_RESET "\n");
                }
                free(col_names[j]);
            }
            free(col_names);
        } else {
            printf("│   └── " COLOR_GRAY "(no collections)" COLOR_RESET "\n");
        }
        free(db_names[i]);
    }
    free(db_names);
    
    printf("\n" COLOR_GREEN "Structure displayed successfully" COLOR_RESET "\n");
}

int get_input(char* buffer, size_t size) {
    if (fgets(buffer, size, stdin) == NULL) {
        return -1;
    }
    
    // Remove newline character
    buffer[strcspn(buffer, "\n")] = '\0';
    return 0;
}

void print_hex_hash(const unsigned char* hash, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x", hash[i]);
        if ((i+1) % 4 == 0) printf(" ");  // Space every 4 bytes
        if ((i+1) % 16 == 0) printf("\n               ");  // Newline every 16 bytes
    }
    printf("\n");
}

void print_proof_details(const MembershipProof* proof) {
    printf(COLOR_CYAN "\n=== Proof Generation Results ===\n\n" COLOR_RESET);
    
    // Basic proof info
    printf(COLOR_YELLOW "Structural Information:\n" COLOR_RESET);
    printf("• Layer Priority:    %d\n", proof->layer_priority);
    printf("• Element Index:     %d\n", proof->element_index);
    
    // Layer root display
    printf(COLOR_YELLOW "\nLayer Merkle Root:\n" COLOR_RESET);
    print_hex_hash(proof->layer_root, HASH_SIZE);
    
    // Proof components analysis
    printf(COLOR_YELLOW "\nProof Composition:\n" COLOR_RESET);
    if (proof->layer_proof_len == 0) {
        printf("• Layer Proof:       " COLOR_GREEN "Not needed " COLOR_RESET);
        printf("(single element in layer)\n");
    } else {
        printf("• Layer Proof:       %zu bytes (merkle path)\n", proof->layer_proof_len);
    }
    
    if (proof->top_level_proof_len == 0) {
        printf("• Top Level Proof:   " COLOR_GREEN "Not needed " COLOR_RESET);
        printf("(only one active layer)\n");
    } else {
        printf("• Top Level Proof:   %zu bytes (%d layer hashes)\n", 
               proof->top_level_proof_len,
               (int)(proof->top_level_proof_len / HASH_SIZE));
    }
    
    // Cryptographic strength info
    printf(COLOR_YELLOW "\nCryptographic Properties:\n" COLOR_RESET);
    printf("• Hash Algorithm:    SHA-256\n");
    printf("• Security Strength: 128-bit collision resistance\n");
}

void print_verification_details(int valid) {
    printf(COLOR_YELLOW "\n=== Verification Result ===\n" COLOR_RESET);
    if (valid) {
        printf(COLOR_GREEN "Proof is VALID\n" COLOR_RESET);
    } else {
        printf(COLOR_RED "Proof is INVALID\n" COLOR_RESET);
    }
}

// Database operation UIs
void create_database_ui() {
    char db_name[MAX_INPUT];
    
    printf(COLOR_CYAN "=== Create Database ===\n\n" COLOR_RESET);
    printf("Enter database name: ");
    get_input(db_name, MAX_INPUT);
    
    db_error_t result = db_create(db_name);
    if (result == DB_SUCCESS) {
        print_status("Database created successfully", 0);
    } else {
        char error_msg[100];
        snprintf(error_msg, sizeof(error_msg), "Failed to create database: %s", 
                db_error_string(result));
        print_status(error_msg, 1);
    }
}

void create_collection_ui() {
    char db_name[MAX_INPUT], col_name[MAX_INPUT];
    
    printf(COLOR_CYAN "=== Create Collection ===\n\n" COLOR_RESET);
    printf("Enter database name: ");
    get_input(db_name, MAX_INPUT);
    printf("Enter collection name: ");
    get_input(col_name, MAX_INPUT);
    
    db_error_t result = db_create_collection(db_name, col_name);
    if (result == DB_SUCCESS) {
        print_status("Collection created successfully", 0);
    } else {
        char error_msg[100];
        snprintf(error_msg, sizeof(error_msg), "Failed to create collection: %s", 
                db_error_string(result));
        print_status(error_msg, 1);
    }
}

void insert_data_ui() {
    char db_name[MAX_INPUT], col_name[MAX_INPUT], key[MAX_INPUT], value[MAX_INPUT*4];
    
    printf(COLOR_CYAN "=== Insert Data ===\n\n" COLOR_RESET);
    printf("Enter database name: ");
    get_input(db_name, MAX_INPUT);
    printf("Enter collection name: ");
    get_input(col_name, MAX_INPUT);
    printf("Enter key: ");
    get_input(key, MAX_INPUT);
    printf("Enter value: ");
    get_input(value, MAX_INPUT*4);
    
    db_error_t result = db_insert(db_name, col_name, key, value);
    if (result == DB_SUCCESS) {
        print_status("Data inserted successfully", 0);
    } else {
        char error_msg[100];
        snprintf(error_msg, sizeof(error_msg), "Failed to insert data: %s", 
                db_error_string(result));
        print_status(error_msg, 1);
    }
}

void find_data_ui() {
    char db_name[MAX_INPUT], col_name[MAX_INPUT], key[MAX_INPUT];
    char* value = NULL;
    
    printf(COLOR_CYAN "=== Find Data ===\n\n" COLOR_RESET);
    printf("Enter database name: ");
    get_input(db_name, MAX_INPUT);
    printf("Enter collection name: ");
    get_input(col_name, MAX_INPUT);
    printf("Enter key: ");
    get_input(key, MAX_INPUT);
    
    db_error_t result = db_find(db_name, col_name, key, &value);
    if (result == DB_SUCCESS && value != NULL) {
        printf(COLOR_CYAN "=== Found Data ===\n\n" COLOR_RESET);
        printf("Key: %s\n", key);
        printf("Value: %s\n\n", value);
        free(value);
        printf("Press Enter to continue...");
        getchar();
    } else {
        char error_msg[100];
        snprintf(error_msg, sizeof(error_msg), "Failed to find data: %s", 
                db_error_string(result));
        print_status(error_msg, 1);
    }
}

void generate_proof_ui() {
    char db_name[MAX_INPUT], col_name[MAX_INPUT], key[MAX_INPUT];
    MembershipProof proof;
    
    printf(COLOR_CYAN "=== Generate Proof ===\n\n" COLOR_RESET);
    printf("Enter database name: ");
    get_input(db_name, MAX_INPUT);
    printf("Enter collection name: ");
    get_input(col_name, MAX_INPUT);
    printf("Enter key: ");
    get_input(key, MAX_INPUT);
    
    db_error_t result = db_generate_proof(db_name, col_name, key, &proof);
    if (result == DB_SUCCESS) {
        printf(COLOR_CYAN "=== Proof Generated ===\n\n" COLOR_RESET);
        print_proof_details(&proof);
        membership_proof_cleanup(&proof);
    } else {
        char error_msg[100];
        snprintf(error_msg, sizeof(error_msg), "Failed to generate proof: %s", 
                db_error_string(result));
        print_status(error_msg, 1);
    }
}

void verify_proof_ui() {
    char db_name[MAX_INPUT], col_name[MAX_INPUT], key[MAX_INPUT], value[MAX_INPUT*4];
    MembershipProof proof;
    int valid = 0;
    
    printf(COLOR_CYAN "=== Verify Proof ===\n\n" COLOR_RESET);
    printf("Enter database name: ");
    get_input(db_name, MAX_INPUT);
    printf("Enter collection name: ");
    get_input(col_name, MAX_INPUT);
    printf("Enter key: ");
    get_input(key, MAX_INPUT);
    printf("Enter expected value: ");
    get_input(value, MAX_INPUT*4);
    
    // First generate the proof
    db_error_t result = db_generate_proof(db_name, col_name, key, &proof);
    if (result != DB_SUCCESS) {
        char error_msg[100];
        snprintf(error_msg, sizeof(error_msg), "Failed to generate proof: %s", 
                db_error_string(result));
        print_status(error_msg, 1);
        return;
    }
    
    // Now verify the proof
    result = db_verify_proof(db_name, col_name, key, value, &proof, &valid);
    membership_proof_cleanup(&proof);
    
    if (result == DB_SUCCESS) {
        printf(COLOR_CYAN "=== Verification Result ===\n\n" COLOR_RESET);
        print_verification_details(valid);
    } else {
        char error_msg[100];
        snprintf(error_msg, sizeof(error_msg), "Verification failed: %s", 
                db_error_string(result));
        print_status(error_msg, 1);
    }
}

void show_stats_ui() {
    char db_name[MAX_INPUT];
    
    printf(COLOR_CYAN "=== Database Statistics ===\n\n" COLOR_RESET);
    printf("Enter database name (or leave blank for all): ");
    get_input(db_name, MAX_INPUT);
    
    if (strlen(db_name) == 0) {
        // Show stats for all databases
        char** db_names = NULL;
        size_t count = 0;
        
        if (db_list(&db_names, &count) == DB_SUCCESS && db_names != NULL) {
            for (size_t i = 0; i < count; i++) {
                DatabaseStats stats;
                if (db_get_stats(db_names[i], &stats) == DB_SUCCESS) {
                    printf("\nDatabase: %s\n", db_names[i]);
                    printf("Created: %s", ctime(&stats.created_at));
                    printf("Last Modified: %s", ctime(&stats.last_modified));
                    printf("Total Records: %zu\n", stats.total_records);
                    printf("Total Collections: %zu\n", stats.total_collections);
                    
                    // Print root hash
                    printf("Root Hash: ");
                    for (int j = 0; j < HASH_SIZE; j++) {
                        printf("%02x", stats.root_hash[j]);
                    }
                    printf("\n");
                }
                free(db_names[i]);
            }
            free(db_names);
        }
    } else {
        // Show stats for specific database
        DatabaseStats stats;
        if (db_get_stats(db_name, &stats) == DB_SUCCESS) {
            printf("\nDatabase: %s\n", db_name);
            printf("Created: %s", ctime(&stats.created_at));
            printf("Last Modified: %s", ctime(&stats.last_modified));
            printf("Total Records: %zu\n", stats.total_records);
            printf("Total Collections: %zu\n", stats.total_collections);
            
            // Print root hash
            printf("Root Hash: ");
            for (int j = 0; j < HASH_SIZE; j++) {
                printf("%02x", stats.root_hash[j]);
            }
            printf("\n");
        } else {
            print_status("Database not found", 1);
            return;
        }
    }
}