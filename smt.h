#ifndef SMT_H
#define SMT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define MAX_LAYERS 256
#define HASH_SIZE 32
#define MAX_KEY_SIZE 256
#define MAX_VALUE_SIZE 1024

typedef enum {
    SMT_SUCCESS = 0,
    SMT_ERROR_NULL_POINTER = -1,
    SMT_ERROR_MEMORY_ALLOCATION = -2,
    SMT_ERROR_INVALID_PARAMETER = -3,
    SMT_ERROR_KEY_NOT_FOUND = -4,
    SMT_ERROR_LAYER_OVERFLOW = -5
} smt_error_t;

typedef struct {
    char* key;
    char* value;
    int priority;
    size_t key_len;
    size_t value_len;
} Element;

typedef struct {
    Element* elements;
    int element_count;
    int capacity;
    unsigned char merkle_root[HASH_SIZE];
    int dirty;
} Layer;

typedef struct {
    int layer_priority;
    int element_index;
    unsigned char layer_root[HASH_SIZE];
    unsigned char* layer_proof;
    size_t layer_proof_len;
    unsigned char* top_level_proof;
    size_t top_level_proof_len;
} MembershipProof;

typedef struct {
    Layer layers[MAX_LAYERS];
    int layer_count;
    unsigned char top_level_root[HASH_SIZE];
    int dirty;
    size_t total_elements;
} SMT;

smt_error_t smt_init(SMT* smt);
void smt_cleanup(SMT* smt);
smt_error_t smt_insert(SMT* smt, const char* key, const char* value);
smt_error_t smt_lookup(const SMT* smt, const char* key, char** value);
smt_error_t smt_delete(SMT* smt, const char* key);
smt_error_t smt_get_root(SMT* smt, unsigned char* root);
smt_error_t smt_generate_proof(const SMT* smt, const char* key, MembershipProof* proof);
smt_error_t smt_verify_proof(const SMT* smt, const char* key, const char* value, 
                            const MembershipProof* proof, int* valid);
void membership_proof_cleanup(MembershipProof* proof);
void smt_print_stats(const SMT* smt);

#endif