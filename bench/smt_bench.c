#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include "smt.h"  // Using your original SMT implementation

#define NUM_ELEMENTS 100000
#define MAX_KEY_SIZE 32
#define MAX_VALUE_SIZE 32

// ================== CMT IMPLEMENTATION ==================
typedef struct CMTNode {
    char key[MAX_KEY_SIZE];
    char value[MAX_VALUE_SIZE];
    int x, y;  // Spatial coordinates for BST ordering
    unsigned char hash[HASH_SIZE];
    struct CMTNode *left, *right;
} CMTNode;

void cmt_hash_node(CMTNode* node) {
    if (!node) return;
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return;
    }
    
    if (node->left) EVP_DigestUpdate(ctx, node->left->hash, HASH_SIZE);
    EVP_DigestUpdate(ctx, node->key, strlen(node->key));
    EVP_DigestUpdate(ctx, node->value, strlen(node->value));
    if (node->right) EVP_DigestUpdate(ctx, node->right->hash, HASH_SIZE);
    EVP_DigestFinal_ex(ctx, node->hash, NULL);
    EVP_MD_CTX_free(ctx);
}

CMTNode* cmt_insert(CMTNode* root, const char* key, const char* value, int x, int y, int* depth, int* max_depth) {
    if (!key || !value) return root;
    
    if (!root) {
        CMTNode* new_node = calloc(1, sizeof(CMTNode));
        if (!new_node) return NULL;
        
        strncpy(new_node->key, key, MAX_KEY_SIZE - 1);
        strncpy(new_node->value, value, MAX_VALUE_SIZE - 1);
        new_node->x = x;
        new_node->y = y;
        cmt_hash_node(new_node);
        if (*depth > *max_depth) *max_depth = *depth;
        return new_node;
    }

    (*depth)++;
    if (x < root->x || (x == root->x && y < root->y)) {
        root->left = cmt_insert(root->left, key, value, x, y, depth, max_depth);
    } else {
        root->right = cmt_insert(root->right, key, value, x, y, depth, max_depth);
    }
    cmt_hash_node(root);
    return root;
}

int cmt_search(CMTNode* root, const char* key) {
    if (!root || !key) return 0;
    if (strcmp(root->key, key) == 0) return 1;
    return cmt_search(root->left, key) || cmt_search(root->right, key);
}

void cmt_cleanup(CMTNode* root) {
    if (!root) return;
    cmt_cleanup(root->left);
    cmt_cleanup(root->right);
    free(root);
}

// ================== BENCHMARK UTILS ==================
double get_time() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

size_t get_memory_usage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss;
}

typedef struct {
    char key[MAX_KEY_SIZE];
    char value[MAX_VALUE_SIZE];
    int x, y;
} TestElement;

void generate_elements(TestElement* elements, int count) {
    for (int i = 0; i < count; i++) {
        snprintf(elements[i].key, MAX_KEY_SIZE, "key_%d", i);
        snprintf(elements[i].value, MAX_VALUE_SIZE, "value_%d", i);
        elements[i].x = rand() % 1000;
        elements[i].y = rand() % 1000;
    }
}

size_t count_cmt_nodes(CMTNode* root) {
    if (!root) return 0;
    return 1 + count_cmt_nodes(root->left) + count_cmt_nodes(root->right);
}

size_t calculate_smt_memory(const SMT* smt) {
    if (!smt) return 0;
    
    size_t total = sizeof(SMT);
    for (int i = 0; i < smt->layer_count; i++) {
        const Layer* layer = &smt->layers[i];
        if (layer->element_count > 0) {
            total += layer->capacity * sizeof(Element);
            // Add memory for key/value strings
            for (int j = 0; j < layer->element_count; j++) {
                total += layer->elements[j].key_len + 1;
                if (layer->elements[j].value) {
                    total += layer->elements[j].value_len + 1;
                }
            }
        }
    }
    return total;
}

// ================== MAIN BENCHMARK ==================
int main() {
    srand(time(NULL));
    TestElement elements[NUM_ELEMENTS];
    generate_elements(elements, NUM_ELEMENTS);

    printf("Generating %d test elements...\n", NUM_ELEMENTS);
    printf("Starting benchmark...\n\n");

    // Benchmark SMT (your implementation)
    SMT smt;
    if (smt_init(&smt) != SMT_SUCCESS) {
        fprintf(stderr, "Failed to initialize SMT\n");
        return 1;
    }

    printf("Testing SMT insertion...\n");
    double start = get_time();
    int smt_insert_failures = 0;
    for (int i = 0; i < NUM_ELEMENTS; i++) {
        if (smt_insert(&smt, elements[i].key, elements[i].value) != SMT_SUCCESS) {
            smt_insert_failures++;
        }
        if (i % 10000 == 0) {
            printf("SMT: Inserted %d elements\n", i);
        }
    }
    double smt_insert_time = get_time() - start;

    printf("Testing SMT search...\n");
    start = get_time();
    volatile int smt_found = 0;
    for (int i = 0; i < NUM_ELEMENTS; i++) {
        char* value = NULL;
        if (smt_lookup(&smt, elements[i].key, &value) == SMT_SUCCESS) {
            smt_found++;
            free(value);
        }
        if (i % 10000 == 0) {
            printf("SMT: Searched %d elements\n", i);
        }
    }
    double smt_search_time = get_time() - start;

    // Benchmark CMT
    CMTNode* cmt_root = NULL;
    int cmt_max_depth = 0;
    printf("Testing CMT insertion...\n");
    start = get_time();
    for (int i = 0; i < NUM_ELEMENTS; i++) {
        int current_depth = 0;
        cmt_root = cmt_insert(cmt_root, elements[i].key, elements[i].value, 
                             elements[i].x, elements[i].y, &current_depth, &cmt_max_depth);
        if (i % 10000 == 0) {
            printf("CMT: Inserted %d elements\n", i);
        }
    }
    double cmt_insert_time = get_time() - start;

    printf("Testing CMT search...\n");
    start = get_time();
    volatile int cmt_found = 0;
    for (int i = 0; i < NUM_ELEMENTS; i++) {
        cmt_found += cmt_search(cmt_root, elements[i].key);
        if (i % 10000 == 0) {
            printf("CMT: Searched %d elements\n", i);
        }
    }
    double cmt_search_time = get_time() - start;

    // Calculate memory usage
    size_t smt_mem = calculate_smt_memory(&smt);
    size_t cmt_mem = count_cmt_nodes(cmt_root) * sizeof(CMTNode);

    // Get root hashes for verification
    unsigned char smt_root[HASH_SIZE];
    smt_error_t root_result = smt_get_root(&smt, smt_root);

    // Print detailed results
    printf("\n============= Benchmark Results (n=%d) =============\n", NUM_ELEMENTS);
    printf("Metric                   SMT                    CMT\n");
    printf("--------------------------------------------------------\n");
    printf("Insert Time:         %10.3f ms         %10.3f ms\n", 
           smt_insert_time * 1000, cmt_insert_time * 1000);
    printf("Search Time:         %10.3f ms         %10.3f ms\n", 
           smt_search_time * 1000, cmt_search_time * 1000);
    printf("Items Found:         %10d             %10d\n", smt_found, cmt_found);
    printf("Max Tree Depth:      %10s             %10d\n", "N/A", cmt_max_depth);
    printf("Memory Usage:        %10zu KB          %10zu KB\n", 
           smt_mem / 1024, cmt_mem / 1024);
    printf("Insert Failures:     %10d             %10s\n", smt_insert_failures, "N/A");

    // Performance ratios
    printf("\n============= Performance Ratios =============\n");
    printf("SMT Insert Speed:    %.2fx %s than CMT\n", 
           smt_insert_time < cmt_insert_time ? 
           cmt_insert_time / smt_insert_time : smt_insert_time / cmt_insert_time,
           smt_insert_time < cmt_insert_time ? "faster" : "slower");
    printf("SMT Search Speed:    %.2fx %s than CMT\n", 
           smt_search_time < cmt_search_time ? 
           cmt_search_time / smt_search_time : smt_search_time / cmt_search_time,
           smt_search_time < cmt_search_time ? "faster" : "slower");
    printf("SMT Memory Usage:    %.2fx %s than CMT\n", 
           smt_mem < cmt_mem ? 
           (double)cmt_mem / smt_mem : (double)smt_mem / cmt_mem,
           smt_mem < cmt_mem ? "less" : "more");

    // Print SMT statistics
    printf("\n============= SMT Detailed Stats =============\n");
    smt_print_stats(&smt);
    
    if (root_result == SMT_SUCCESS) {
        printf("SMT Root Hash: ");
        for (int i = 0; i < 8; i++) printf("%02x", smt_root[i]);
        printf("...\n");
    } else {
        printf("SMT Root Hash: <calculation failed>\n");
    }

    printf("\n============= CMT Detailed Stats =============\n");
    printf("Total Nodes: %zu\n", count_cmt_nodes(cmt_root));
    printf("Max Depth: %d\n", cmt_max_depth);
    printf("Memory per Node: %zu bytes\n", sizeof(CMTNode));

    // Cleanup
    smt_cleanup(&smt);
    cmt_cleanup(cmt_root);

    return 0;
}