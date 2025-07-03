// smt.c (optimized)
#include "smt.h"

static void safe_hash(const void* data, size_t len, unsigned char* hash);
static void element_cleanup(Element* element);

static int compute_priority(const char* key) {
    if (!key) return 0;
    
    unsigned char hash[HASH_SIZE];
    safe_hash(key, strlen(key), hash);
    
    printf("Key: '%s' | Hash: ", key);
    for (int i = 0; i < 4; i++) printf("%02x", hash[i]);
    printf(" | ");
    
    uint32_t priority = 0;
    for (int i = 0; i < 4; i++) {
        priority = (priority << 8) | hash[i];
    }
    
    // Ensure layer index is within bounds
    int layer = priority % MAX_LAYERS;
    if (layer < 0) layer = 0;
    if (layer >= MAX_LAYERS) layer = MAX_LAYERS - 1;
    
    printf("Priority: %u | Layer: %d\n", priority, layer);
    return layer;
}
static void safe_hash(const void* data, size_t len, unsigned char* hash) {
    if (!data || !hash || len == 0) {
        memset(hash, 0, HASH_SIZE);
        return;
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx) {
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
            EVP_DigestUpdate(ctx, data, len) == 1) {
            unsigned int hash_len;
            EVP_DigestFinal_ex(ctx, hash, &hash_len);
        } else {
            memset(hash, 0, HASH_SIZE);
        }
        EVP_MD_CTX_free(ctx);
    } else {
        SHA256((const unsigned char*)data, len, hash);
    }
}

static smt_error_t layer_init(Layer* layer) {
    if (!layer) return SMT_ERROR_NULL_POINTER;
    
    layer->elements = NULL;
    layer->element_count = 0;
    layer->capacity = 0;
    layer->dirty = 1;
    memset(layer->merkle_root, 0, HASH_SIZE);
    
    return SMT_SUCCESS;
}

static void element_cleanup(Element* element) {
    if (!element) return;
    
    free(element->key);
    free(element->value);
    memset(element, 0, sizeof(Element));
}

static void layer_cleanup(Layer* layer) {
    if (!layer) return;
    
    for (int i = 0; i < layer->element_count; i++) {
        element_cleanup(&layer->elements[i]);
    }
    
    free(layer->elements);
    layer->elements = NULL;
    layer->element_count = 0;
    layer->capacity = 0;
}

// Binary search implementation for finding elements
static int find_element_in_layer(const Layer* layer, const char* key) {
    if (!layer || !key) return -1;
    
    int low = 0;
    int high = layer->element_count - 1;
    
    while (low <= high) {
        int mid = low + (high - low) / 2;
        int cmp = strcmp(layer->elements[mid].key, key);
        
        if (cmp == 0) {
            return mid;
        } else if (cmp < 0) {
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }
    
    return -1;
}

// Insert element in sorted order
static smt_error_t layer_add_element(Layer* layer, const char* key, const char* value, int priority) {
    if (!layer || !key) return SMT_ERROR_NULL_POINTER;
    
    // Check if we need to expand capacity
    if (layer->element_count >= layer->capacity) {
        int new_capacity = layer->capacity == 0 ? 8 : layer->capacity * 2;
        Element* new_elements = realloc(layer->elements, sizeof(Element) * new_capacity);
        if (!new_elements) return SMT_ERROR_MEMORY_ALLOCATION;
        
        layer->elements = new_elements;
        layer->capacity = new_capacity;
    }
    
    // Find insertion position
    int insert_pos = 0;
    while (insert_pos < layer->element_count && 
           strcmp(layer->elements[insert_pos].key, key) < 0) {
        insert_pos++;
    }
    
    // Shift elements to make space if needed
    if (insert_pos < layer->element_count) {
        memmove(&layer->elements[insert_pos+1], 
                &layer->elements[insert_pos],
                (layer->element_count - insert_pos) * sizeof(Element));
    }
    
    // Initialize new element at the correct position
    Element* elem = &layer->elements[insert_pos];
    
    elem->key_len = strlen(key);
    elem->key = malloc(elem->key_len + 1);
    if (!elem->key) return SMT_ERROR_MEMORY_ALLOCATION;
    strcpy(elem->key, key);
    
    if (value) {
        elem->value_len = strlen(value);
        elem->value = malloc(elem->value_len + 1);
        if (!elem->value) {
            free(elem->key);
            return SMT_ERROR_MEMORY_ALLOCATION;
        }
        strcpy(elem->value, value);
    } else {
        elem->value = NULL;
        elem->value_len = 0;
    }
    
    elem->priority = priority;
    layer->element_count++;
    layer->dirty = 1;
    
    return SMT_SUCCESS;
}

static smt_error_t calculate_layer_merkle_root(Layer* layer) {
    if (!layer) return SMT_ERROR_NULL_POINTER;
    
    if (!layer->dirty) return SMT_SUCCESS;
    
    if (layer->element_count == 0) {
        memset(layer->merkle_root, 0, HASH_SIZE);
        layer->dirty = 0;
        return SMT_SUCCESS;
    }
    
    // CRITICAL FIX: For single element, the layer root is the element hash itself
    if (layer->element_count == 1) {
        Element* elem = &layer->elements[0];
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            // Fallback to old SHA256 API
            SHA256_CTX old_ctx;
            SHA256_Init(&old_ctx);
            SHA256_Update(&old_ctx, elem->key, elem->key_len);
            if (elem->value) {
                SHA256_Update(&old_ctx, elem->value, elem->value_len);
            }
            SHA256_Update(&old_ctx, &elem->priority, sizeof(elem->priority));
            SHA256_Final(layer->merkle_root, &old_ctx);
            layer->dirty = 0;
            return SMT_SUCCESS;
        }
        
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
            EVP_DigestUpdate(ctx, elem->key, elem->key_len) == 1 &&
            (!elem->value || EVP_DigestUpdate(ctx, elem->value, elem->value_len) == 1) &&
            EVP_DigestUpdate(ctx, &elem->priority, sizeof(elem->priority)) == 1) {
            unsigned int hash_len;
            EVP_DigestFinal_ex(ctx, layer->merkle_root, &hash_len);
        } else {
            memset(layer->merkle_root, 0, HASH_SIZE);
        }
        
        EVP_MD_CTX_free(ctx);
        layer->dirty = 0;
        return SMT_SUCCESS;
    }
    
    // For multiple elements, first hash each element, then hash all element hashes together
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        // Fallback implementation
        SHA256_CTX old_ctx;
        SHA256_Init(&old_ctx);
        
        // Hash each element individually, then combine
        for (int i = 0; i < layer->element_count; i++) {
            Element* elem = &layer->elements[i];
            unsigned char element_hash[HASH_SIZE];
            
            SHA256_CTX elem_ctx;
            SHA256_Init(&elem_ctx);
            SHA256_Update(&elem_ctx, elem->key, elem->key_len);
            if (elem->value) {
                SHA256_Update(&elem_ctx, elem->value, elem->value_len);
            }
            SHA256_Update(&elem_ctx, &elem->priority, sizeof(elem->priority));
            SHA256_Final(element_hash, &elem_ctx);
            
            SHA256_Update(&old_ctx, element_hash, HASH_SIZE);
        }
        
        SHA256_Final(layer->merkle_root, &old_ctx);
        layer->dirty = 0;
        return SMT_SUCCESS;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1) {
        // Hash each element individually, then combine
        for (int i = 0; i < layer->element_count; i++) {
            Element* elem = &layer->elements[i];
            unsigned char element_hash[HASH_SIZE];
            
            EVP_MD_CTX* elem_ctx = EVP_MD_CTX_new();
            if (elem_ctx && 
                EVP_DigestInit_ex(elem_ctx, EVP_sha256(), NULL) == 1 &&
                EVP_DigestUpdate(elem_ctx, elem->key, elem->key_len) == 1 &&
                (!elem->value || EVP_DigestUpdate(elem_ctx, elem->value, elem->value_len) == 1) &&
                EVP_DigestUpdate(elem_ctx, &elem->priority, sizeof(elem->priority)) == 1) {
                unsigned int hash_len;
                EVP_DigestFinal_ex(elem_ctx, element_hash, &hash_len);
                EVP_DigestUpdate(ctx, element_hash, HASH_SIZE);
            }
            if (elem_ctx) EVP_MD_CTX_free(elem_ctx);
        }
        
        unsigned int hash_len;
        EVP_DigestFinal_ex(ctx, layer->merkle_root, &hash_len);
    }
    
    EVP_MD_CTX_free(ctx);
    layer->dirty = 0;
    
    return SMT_SUCCESS;
}

static void print_hash(const char* label, const unsigned char* hash) {
    printf("%s: ", label);
    for (int i = 0; i < HASH_SIZE; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

// Add these helper functions to smt.c (before the public functions)

// Fixed proof generation and verification functions for smt.c

// Replace the existing generate_layer_proof function with this corrected version
static smt_error_t generate_layer_proof(const Layer* layer, int element_index, 
                                      unsigned char** proof, size_t* proof_len) {
    if (!layer || !proof || !proof_len) return SMT_ERROR_NULL_POINTER;
    if (element_index < 0 || element_index >= layer->element_count) {
        return SMT_ERROR_INVALID_PARAMETER;
    }

    // For a single element in the layer, no layer proof is needed
    if (layer->element_count == 1) {
        *proof = NULL;
        *proof_len = 0;
        return SMT_SUCCESS;
    }

    // Calculate required proof size (element hashes for all elements except the target)
    size_t required_size = (layer->element_count - 1) * HASH_SIZE;
    *proof = malloc(required_size);
    if (!*proof) return SMT_ERROR_MEMORY_ALLOCATION;
    *proof_len = required_size;

    unsigned char* proof_ptr = *proof;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        free(*proof);
        *proof = NULL;
        return SMT_ERROR_MEMORY_ALLOCATION;
    }

    // Hash all elements except the target - store individual element hashes
    for (int i = 0; i < layer->element_count; i++) {
        if (i == element_index) continue;

        Element* elem = &layer->elements[i];
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
            EVP_MD_CTX_free(ctx);
            free(*proof);
            *proof = NULL;
            return SMT_ERROR_INVALID_PARAMETER;
        }

        // Hash the individual element
        if (EVP_DigestUpdate(ctx, elem->key, elem->key_len) != 1 ||
            (elem->value && EVP_DigestUpdate(ctx, elem->value, elem->value_len) != 1) ||
            EVP_DigestUpdate(ctx, &elem->priority, sizeof(elem->priority)) != 1) {
            EVP_MD_CTX_free(ctx);
            free(*proof);
            *proof = NULL;
            return SMT_ERROR_INVALID_PARAMETER;
        }

        unsigned int hash_len;
        if (EVP_DigestFinal_ex(ctx, proof_ptr, &hash_len) != 1) {
            EVP_MD_CTX_free(ctx);
            free(*proof);
            *proof = NULL;
            return SMT_ERROR_INVALID_PARAMETER;
        }
        proof_ptr += HASH_SIZE;
    }

    EVP_MD_CTX_free(ctx);
    return SMT_SUCCESS;
}

static smt_error_t generate_top_level_proof(const SMT* smt, int layer_index,
                                          unsigned char** proof, size_t* proof_len) {
    if (!smt || !proof || !proof_len) return SMT_ERROR_NULL_POINTER;
    if (layer_index < 0 || layer_index >= smt->layer_count) {
        return SMT_ERROR_INVALID_PARAMETER;
    }

    // CRITICAL FIX: Ensure all layer merkle roots are calculated before generating proof
    SMT* mutable_smt = (SMT*)smt;  // Cast away const for calculation
    for (int i = 0; i < smt->layer_count; i++) {
        if (smt->layers[i].element_count > 0) {
            smt_error_t err = calculate_layer_merkle_root(&mutable_smt->layers[i]);
            if (err != SMT_SUCCESS) return err;
        }
    }

    // Count active layers (excluding our target layer)
    int active_layers = 0;
    for (int i = 0; i < smt->layer_count; i++) {
        if (i != layer_index && smt->layers[i].element_count > 0) {
            active_layers++;
        }
    }

    size_t required_size = active_layers * HASH_SIZE;
    *proof = malloc(required_size);
    if (!*proof) return SMT_ERROR_MEMORY_ALLOCATION;
    *proof_len = required_size;

    unsigned char* proof_ptr = *proof;
    for (int i = 0; i < smt->layer_count; i++) {
        if (i == layer_index || smt->layers[i].element_count == 0) continue;

        memcpy(proof_ptr, smt->layers[i].merkle_root, HASH_SIZE);
        proof_ptr += HASH_SIZE;
    }

    return SMT_SUCCESS;
}

static smt_error_t verify_layer_proof(const Layer* layer, int element_index,
                                     const unsigned char* proof, size_t proof_len,
                                     const unsigned char* expected_root) {
    if (!layer || !expected_root) return SMT_ERROR_NULL_POINTER;
    if (element_index < 0 || element_index >= layer->element_count) {
        printf("DEBUG: Invalid element index %d (count: %d)\n", element_index, layer->element_count);
        return SMT_ERROR_INVALID_PARAMETER;
    }

    printf("DEBUG: Verifying layer proof for element %d in layer with %d elements\n",
           element_index, layer->element_count);
    print_hash("Expected layer root", expected_root);

    // CRITICAL FIX: For single element layers, no proof is needed - just verify the element hash
    if (layer->element_count == 1) {
        if (proof_len != 0) {
            printf("DEBUG: Single element layer should have no proof, got %zu bytes\n", proof_len);
            return SMT_ERROR_INVALID_PARAMETER;
        }
        
        // Calculate the hash of the single element - this should match the layer root
        Element* elem = &layer->elements[element_index];
        unsigned char element_hash[HASH_SIZE];
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return SMT_ERROR_MEMORY_ALLOCATION;

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
            EVP_DigestUpdate(ctx, elem->key, elem->key_len) != 1 ||
            (elem->value && EVP_DigestUpdate(ctx, elem->value, elem->value_len) != 1) ||
            EVP_DigestUpdate(ctx, &elem->priority, sizeof(elem->priority)) != 1) {
            EVP_MD_CTX_free(ctx);
            printf("DEBUG: Failed to hash single element\n");
            return SMT_ERROR_INVALID_PARAMETER;
        }

        unsigned int hash_len;
        if (EVP_DigestFinal_ex(ctx, element_hash, &hash_len) != 1) {
            EVP_MD_CTX_free(ctx);
            printf("DEBUG: Failed to finalize single element hash\n");
            return SMT_ERROR_INVALID_PARAMETER;
        }
        EVP_MD_CTX_free(ctx);

        print_hash("Single element hash", element_hash);
        int match = memcmp(element_hash, expected_root, HASH_SIZE) == 0;
        printf("DEBUG: Single element verification %s\n", match ? "PASSED" : "FAILED");
        return match ? SMT_SUCCESS : SMT_ERROR_INVALID_PARAMETER;
    }

    // For multi-element layers, verify the proof length
    if (proof_len != (layer->element_count - 1) * HASH_SIZE) {
    printf("DEBUG: Proof length mismatch - expected %zu, got %zu\n",
           (size_t)(layer->element_count - 1) * HASH_SIZE, proof_len);
        return SMT_ERROR_INVALID_PARAMETER;
    }

    // Calculate the hash of the target element
    Element* elem = &layer->elements[element_index];
    unsigned char element_hash[HASH_SIZE];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return SMT_ERROR_MEMORY_ALLOCATION;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, elem->key, elem->key_len) != 1 ||
        (elem->value && EVP_DigestUpdate(ctx, elem->value, elem->value_len) != 1) ||
        EVP_DigestUpdate(ctx, &elem->priority, sizeof(elem->priority)) != 1) {
        EVP_MD_CTX_free(ctx);
        printf("DEBUG: Failed to hash target element\n");
        return SMT_ERROR_INVALID_PARAMETER;
    }

    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, element_hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        printf("DEBUG: Failed to finalize target element hash\n");
        return SMT_ERROR_INVALID_PARAMETER;
    }
    EVP_MD_CTX_reset(ctx);

    // Collect all element hashes in sorted order (by key)
    unsigned char* all_hashes = malloc(layer->element_count * HASH_SIZE);
    if (!all_hashes) {
        EVP_MD_CTX_free(ctx);
        return SMT_ERROR_MEMORY_ALLOCATION;
    }

    // Copy proof hashes and insert target element hash
    int proof_index = 0;
    for (int i = 0; i < layer->element_count; i++) {
        if (i == element_index) {
            memcpy(all_hashes + i * HASH_SIZE, element_hash, HASH_SIZE);
        } else {
            if (proof_index >= proof_len / HASH_SIZE) {
                free(all_hashes);
                EVP_MD_CTX_free(ctx);
                printf("DEBUG: Proof index out of bounds\n");
                return SMT_ERROR_INVALID_PARAMETER;
            }
            memcpy(all_hashes + i * HASH_SIZE, proof + proof_index * HASH_SIZE, HASH_SIZE);
            proof_index++;
        }
    }

    // Recompute the layer's Merkle root
    unsigned char computed_root[HASH_SIZE];
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        free(all_hashes);
        EVP_MD_CTX_free(ctx);
        printf("DEBUG: Failed to initialize hash context\n");
        return SMT_ERROR_INVALID_PARAMETER;
    }

    for (int i = 0; i < layer->element_count; i++) {
        if (EVP_DigestUpdate(ctx, all_hashes + i * HASH_SIZE, HASH_SIZE) != 1) {
            free(all_hashes);
            EVP_MD_CTX_free(ctx);
            printf("DEBUG: Failed to update hash\n");
            return SMT_ERROR_INVALID_PARAMETER;
        }
    }

    if (EVP_DigestFinal_ex(ctx, computed_root, &hash_len) != 1) {
        free(all_hashes);
        EVP_MD_CTX_free(ctx);
        printf("DEBUG: Failed to finalize computed root\n");
        return SMT_ERROR_INVALID_PARAMETER;
    }

    free(all_hashes);
    EVP_MD_CTX_free(ctx);

    print_hash("Computed layer root", computed_root);
    int match = memcmp(computed_root, expected_root, HASH_SIZE) == 0;
    printf("DEBUG: Layer verification %s\n", match ? "PASSED" : "FAILED");
    return match ? SMT_SUCCESS : SMT_ERROR_INVALID_PARAMETER;
}

// Implement the public proof functions

smt_error_t smt_generate_proof(const SMT* smt, const char* key, MembershipProof* proof) {
    if (!smt || !key || !proof) return SMT_ERROR_NULL_POINTER;
    
    // Clear the proof structure
    memset(proof, 0, sizeof(MembershipProof));
    
    // Find the element first
    unsigned char hash[HASH_SIZE];
    safe_hash(key, strlen(key), hash);
    
    uint32_t priority = 0;
    for (int i = 0; i < 4; i++) {
        priority = (priority << 8) | hash[i];
    }
    int layer_index = priority % MAX_LAYERS;
    
    if (layer_index < 0 || layer_index >= smt->layer_count) {
        return SMT_ERROR_KEY_NOT_FOUND;
    }
    
    Layer* layer = &smt->layers[layer_index];  // Cast away const for calculation
    int element_index = find_element_in_layer(layer, key);
    if (element_index < 0) {
        return SMT_ERROR_KEY_NOT_FOUND;
    }
    
    // CRITICAL FIX: Calculate and store the layer's merkle root in the proof
    smt_error_t err = calculate_layer_merkle_root(layer);
    if (err != SMT_SUCCESS) {
        return err;
    }
    
    // Store the calculated layer root in the proof
    memcpy(proof->layer_root, layer->merkle_root, HASH_SIZE);
    
    // Generate layer proof
    err = generate_layer_proof(layer, element_index, 
                              &proof->layer_proof, &proof->layer_proof_len);
    if (err != SMT_SUCCESS) {
        return err;
    }
    
    // Generate top level proof
    err = generate_top_level_proof(smt, layer_index,
                                  &proof->top_level_proof, &proof->top_level_proof_len);
    if (err != SMT_SUCCESS) {
        free(proof->layer_proof);
        memset(proof, 0, sizeof(MembershipProof));
        return err;
    }
    
    // Store additional proof metadata
    proof->layer_priority = layer_index;
    proof->element_index = element_index;
    
    return SMT_SUCCESS;
}
smt_error_t smt_verify_proof(const SMT* smt, const char* key, const char* value, 
                            const MembershipProof* proof, int* valid) {
    if (!smt || !key || !proof || !valid) return SMT_ERROR_NULL_POINTER;
    *valid = 0;
    
    printf("DEBUG: Starting proof verification for key '%s'\n", key);
    printf("DEBUG: Proof layer_priority: %d, element_index: %d\n", 
           proof->layer_priority, proof->element_index);
    
    // Verify the layer proof first
    if (proof->layer_priority < 0 || proof->layer_priority >= smt->layer_count) {
        printf("DEBUG: Invalid layer priority %d (max: %d)\n", proof->layer_priority, smt->layer_count);
        return SMT_ERROR_INVALID_PARAMETER;
    }
    
    const Layer* layer = &smt->layers[proof->layer_priority];
    if (proof->element_index < 0 || proof->element_index >= layer->element_count) {
        printf("DEBUG: Invalid element index %d (count: %d)\n", proof->element_index, layer->element_count);
        return SMT_ERROR_INVALID_PARAMETER;
    }
    
    // Check the key matches
    const Element* elem = &layer->elements[proof->element_index];
    if (strcmp(elem->key, key) != 0) {
        printf("DEBUG: Key mismatch - expected '%s', got '%s'\n", key, elem->key);
        return SMT_SUCCESS; // Not valid, but no error
    }
    
    // Check the value matches if provided
    if (value && (!elem->value || strcmp(elem->value, value) != 0)) {
        printf("DEBUG: Value mismatch - expected '%s', got '%s'\n", 
               value, elem->value ? elem->value : "NULL");
        return SMT_SUCCESS; // Not valid, but no error
    }
    
    printf("DEBUG: Key and value match, verifying layer proof\n");
    print_hash("Proof layer root", proof->layer_root);
    
    // First, let's verify that the proof layer root matches the actual layer root
    unsigned char actual_layer_root[HASH_SIZE];
    Layer* mutable_layer = (Layer*)layer;  // Cast away const for calculation
    smt_error_t err = calculate_layer_merkle_root(mutable_layer);
    if (err != SMT_SUCCESS) {
        printf("DEBUG: Failed to calculate actual layer root\n");
        return err;
    }
    memcpy(actual_layer_root, layer->merkle_root, HASH_SIZE);
    print_hash("Actual layer root", actual_layer_root);
    
    if (memcmp(proof->layer_root, actual_layer_root, HASH_SIZE) != 0) {
        printf("DEBUG: Proof layer root doesn't match actual layer root\n");
        return SMT_ERROR_INVALID_PARAMETER;
    }
    
    // Verify the layer proof against the stored layer root
    err = verify_layer_proof(layer, proof->element_index,
                           proof->layer_proof, proof->layer_proof_len,
                           proof->layer_root);
    if (err != SMT_SUCCESS) {
        printf("DEBUG: Layer proof verification failed with error %d\n", err);
        return err;
    }
    
    printf("DEBUG: Layer proof verified successfully\n");
    
    // Now verify the top level proof
    printf("DEBUG: Verifying top-level proof\n");
    printf("DEBUG: Top-level proof length: %zu bytes (%zu hashes)\n", 
           proof->top_level_proof_len, proof->top_level_proof_len / HASH_SIZE);
    
    // Count active layers
    int active_layers = 0;
    for (int i = 0; i < smt->layer_count; i++) {
        if (smt->layers[i].element_count > 0) {
            active_layers++;
            printf("DEBUG: Active layer %d with %d elements\n", i, smt->layers[i].element_count);
        }
    }
    printf("DEBUG: Total active layers: %d\n", active_layers);
    
    // Expected proof length should be (active_layers - 1) * HASH_SIZE
    size_t expected_proof_len = (active_layers - 1) * HASH_SIZE;
    if (proof->top_level_proof_len != expected_proof_len) {
        printf("DEBUG: Top-level proof length mismatch - expected %zu, got %zu\n", 
               expected_proof_len, proof->top_level_proof_len);
        return SMT_ERROR_INVALID_PARAMETER;
    }
    
    // Reconstruct the top-level root
    unsigned char computed_top_root[HASH_SIZE];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return SMT_ERROR_MEMORY_ALLOCATION;
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return SMT_ERROR_INVALID_PARAMETER;
    }
    
    const unsigned char* proof_ptr = proof->top_level_proof;
    int proof_index = 0;
    
    printf("DEBUG: Reconstructing top-level root:\n");
    for (int i = 0; i < smt->layer_count; i++) {
        if (smt->layers[i].element_count == 0) continue;
        
        if (i == proof->layer_priority) {
            printf("DEBUG: Adding target layer %d root\n", i);
            print_hash("  Target layer root", proof->layer_root);
            if (EVP_DigestUpdate(ctx, proof->layer_root, HASH_SIZE) != 1) {
                EVP_MD_CTX_free(ctx);
                return SMT_ERROR_INVALID_PARAMETER;
            }
        } else {
            printf("DEBUG: Adding proof layer %d root (proof index %d)\n", i, proof_index);
            if (proof_index >= proof->top_level_proof_len / HASH_SIZE) {
                printf("DEBUG: Proof index out of bounds\n");
                EVP_MD_CTX_free(ctx);
                return SMT_ERROR_INVALID_PARAMETER;
            }
            print_hash("  Proof layer root", proof_ptr + (proof_index * HASH_SIZE));
            if (EVP_DigestUpdate(ctx, proof_ptr + (proof_index * HASH_SIZE), HASH_SIZE) != 1) {
                EVP_MD_CTX_free(ctx);
                return SMT_ERROR_INVALID_PARAMETER;
            }
            proof_index++;
        }
    }
    
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, computed_top_root, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return SMT_ERROR_INVALID_PARAMETER;
    }
    EVP_MD_CTX_free(ctx);
    
    print_hash("Computed top-level root", computed_top_root);
    
    // Get the actual top root
    unsigned char actual_top_root[HASH_SIZE];
    err = smt_get_root((SMT*)smt, actual_top_root);
    if (err != SMT_SUCCESS) {
        printf("DEBUG: Failed to get actual top root\n");
        return err;
    }
    
    print_hash("Actual top-level root", actual_top_root);
    
    *valid = memcmp(computed_top_root, actual_top_root, HASH_SIZE) == 0;
    printf("DEBUG: Top-level verification %s\n", *valid ? "PASSED" : "FAILED");
    
    return SMT_SUCCESS;
}
// Add this cleanup function for MembershipProof
void membership_proof_cleanup(MembershipProof* proof) {
    if (!proof) return;
    
    free(proof->layer_proof);
    free(proof->top_level_proof);
    memset(proof, 0, sizeof(MembershipProof));
}


static smt_error_t update_top_level_root(SMT* smt) {
    if (!smt) return SMT_ERROR_NULL_POINTER;
    
    if (!smt->dirty) return SMT_SUCCESS;
    
    int active_layers = 0;
    
    for (int i = 0; i < smt->layer_count; i++) {
        if (smt->layers[i].element_count > 0) {
            smt_error_t err = calculate_layer_merkle_root(&smt->layers[i]);
            if (err != SMT_SUCCESS) return err;
            active_layers++;
        }
    }
    
    if (active_layers == 0) {
        memset(smt->top_level_root, 0, HASH_SIZE);
    } else {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1) {
            for (int i = 0; i < smt->layer_count; i++) {
                if (smt->layers[i].element_count > 0) {
                    EVP_DigestUpdate(ctx, smt->layers[i].merkle_root, HASH_SIZE);
                }
            }
            
            unsigned int hash_len;
            EVP_DigestFinal_ex(ctx, smt->top_level_root, &hash_len);
            EVP_MD_CTX_free(ctx);
        } else {
            SHA256_CTX old_ctx;
            SHA256_Init(&old_ctx);
            
            for (int i = 0; i < smt->layer_count; i++) {
                if (smt->layers[i].element_count > 0) {
                    SHA256_Update(&old_ctx, smt->layers[i].merkle_root, HASH_SIZE);
                }
            }
            
            SHA256_Final(smt->top_level_root, &old_ctx);
            if (ctx) EVP_MD_CTX_free(ctx);
        }
    }
    
    smt->dirty = 0;
    return SMT_SUCCESS;
}

smt_error_t smt_init(SMT* smt) {
    if (!smt) return SMT_ERROR_NULL_POINTER;
    
    memset(smt, 0, sizeof(SMT));
    
    for (int i = 0; i < MAX_LAYERS; i++) {
        smt_error_t err = layer_init(&smt->layers[i]);
        if (err != SMT_SUCCESS) {
            for (int j = 0; j < i; j++) {
                layer_cleanup(&smt->layers[j]);
            }
            return err;
        }
    }
    
    smt->layer_count = 0;
    smt->dirty = 1;
    smt->total_elements = 0;
    memset(smt->top_level_root, 0, HASH_SIZE);
    
    return SMT_SUCCESS;
}

void smt_cleanup(SMT* smt) {
    if (!smt) return;
    
    for (int i = 0; i < MAX_LAYERS; i++) {
        layer_cleanup(&smt->layers[i]);
    }
    
    memset(smt, 0, sizeof(SMT));
}

smt_error_t layer_resize(Layer* layer) {
    if (!layer) {
        fprintf(stderr, "[ERROR] layer_resize: Null layer\n");
        return SMT_ERROR_NULL_POINTER;
    }
    
    int new_capacity = layer->capacity == 0 ? 8 : layer->capacity * 2;
    if (new_capacity > 1000000) { // Arbitrary limit to prevent excessive allocation
        fprintf(stderr, "[ERROR] layer_resize: New capacity %d exceeds limit\n", new_capacity);
        return SMT_ERROR_LAYER_OVERFLOW;
    }
    
    Element* new_elements = realloc(layer->elements, sizeof(Element) * new_capacity);
    if (!new_elements) {
        fprintf(stderr, "[ERROR] layer_resize: Memory allocation failed\n");
        return SMT_ERROR_MEMORY_ALLOCATION;
    }
    
    layer->elements = new_elements;
    layer->capacity = new_capacity;
    fprintf(stdout, "[DEBUG] layer_resize: Resized to capacity=%d\n", new_capacity);
    return SMT_SUCCESS;
}

smt_error_t smt_insert(SMT* smt, const char* key, const char* value) {
    fprintf(stdout, "[DEBUG] smt_insert: Starting for key='%s'\n", key);
    if (!smt || !key) {
        fprintf(stderr, "[ERROR] smt_insert: Null pointer detected\n");
        return SMT_ERROR_NULL_POINTER;
    }
    
    if (strlen(key) >= 256) {
        fprintf(stderr, "[ERROR] smt_insert: Key length exceeds 256 for '%s'\n", key);
        return SMT_ERROR_INVALID_PARAMETER;
    }

    int priority = compute_priority(key);
    if (priority < 0 || priority >= MAX_LAYERS) {
        fprintf(stderr, "[ERROR] smt_insert: Invalid priority %d for key '%s'\n", priority, key);
        return SMT_ERROR_INVALID_PARAMETER;
    }
    
    fprintf(stdout, "[DEBUG] smt_insert: Computed priority=%d\n", priority);
    
    if (priority >= smt->layer_count) {
        fprintf(stdout, "[DEBUG] smt_insert: Extending layer_count to %d\n", priority + 1);
        smt->layer_count = priority + 1;
    }
    
    Layer* layer = &smt->layers[priority];
    fprintf(stdout, "[DEBUG] smt_insert: Accessing layer at priority %d\n", priority);
    
    uint32_t max_iterations = 1000; // Arbitrary limit to prevent infinite loops
    uint32_t iteration = 0;
    while (layer->element_count >= layer->capacity && iteration < max_iterations) {
        fprintf(stdout, "[DEBUG] smt_insert: Layer full, resizing (iteration %u)\n", iteration);
        smt_error_t resize_err = layer_resize(layer);
        if (resize_err != SMT_SUCCESS) {
            fprintf(stderr, "[ERROR] smt_insert: Layer resize failed, error=%d\n", resize_err);
            return resize_err;
        }
        iteration++;
    }
    if (iteration >= max_iterations) {
        fprintf(stderr, "[ERROR] smt_insert: Exceeded max iterations for layer resize\n");
        return SMT_ERROR_INFINITE_LOOP;
    }

    int existing_index = find_element_in_layer(layer, key);
    fprintf(stdout, "[DEBUG] smt_insert: Existing index=%d for key '%s'\n", existing_index, key);
    
    if (existing_index >= 0) {
        Element* elem = &layer->elements[existing_index];
        fprintf(stdout, "[DEBUG] smt_insert: Updating existing element\n");
        free(elem->value);
        
        if (value) {
            elem->value_len = strlen(value);
            elem->value = malloc(elem->value_len + 1);
            if (!elem->value) {
                fprintf(stderr, "[ERROR] smt_insert: Memory allocation failed\n");
                return SMT_ERROR_MEMORY_ALLOCATION;
            }
            strcpy(elem->value, value);
        } else {
            elem->value = NULL;
            elem->value_len = 0;
        }
        
        layer->dirty = 1;
        smt->dirty = 1;
    } else {
        fprintf(stdout, "[DEBUG] smt_insert: Adding new element\n");
        smt_error_t err = layer_add_element(layer, key, value, priority);
        if (err != SMT_SUCCESS) {
            fprintf(stderr, "[ERROR] smt_insert: Failed to add element, error=%d\n", err);
            return err;
        }
        
        smt->total_elements++;
        smt->dirty = 1;
    }
    
    fprintf(stdout, "[DEBUG] smt_insert: Completed for key '%s'\n", key);
    return SMT_SUCCESS;
}

smt_error_t smt_lookup(const SMT* smt, const char* key, char** value) {
    if (!smt || !key || !value) return SMT_ERROR_NULL_POINTER;
    
    *value = NULL;
    
    unsigned char hash[HASH_SIZE];
    safe_hash(key, strlen(key), hash);
    printf("Key: '%s' | Hash: ", key);
    for (int i = 0; i < 4; i++) printf("%02x", hash[i]);
    printf(" | ");
    
    uint32_t priority = 0;
    for (int i = 0; i < 4; i++) {
        priority = (priority << 8) | hash[i];
    }
    int layer = priority % MAX_LAYERS;
    printf("Priority: %u | Layer: %d | ", priority, layer);
    
    if (layer < 0 || layer >= smt->layer_count) {
        printf("Key not found (invalid layer)\n");
        return SMT_ERROR_KEY_NOT_FOUND;
    }
    
    const Layer* layer_ptr = &smt->layers[layer];
    int index = find_element_in_layer(layer_ptr, key);
    
    if (index < 0) {
        printf("Key not found (missing in layer)\n");
        return SMT_ERROR_KEY_NOT_FOUND;
    }
    
    const Element* elem = &layer_ptr->elements[index];
    if (elem->value) {
        *value = malloc(elem->value_len + 1);
        if (!*value) return SMT_ERROR_MEMORY_ALLOCATION;
        strcpy(*value, elem->value);
        printf("Found value: '%s'\n", *value);
    } else {
        printf("Found NULL value\n");
    }
    
    return SMT_SUCCESS;
}

smt_error_t smt_delete(SMT* smt, const char* key) {
    if (!smt || !key) return SMT_ERROR_NULL_POINTER;
    
    int priority = compute_priority(key);
    if (priority < 0 || priority >= smt->layer_count) return SMT_ERROR_KEY_NOT_FOUND;
    
    Layer* layer = &smt->layers[priority];
    int index = find_element_in_layer(layer, key);
    
    if (index < 0) return SMT_ERROR_KEY_NOT_FOUND;
    
    element_cleanup(&layer->elements[index]);
    
    // Shift remaining elements to maintain sorted order
    if (index < layer->element_count - 1) {
        memmove(&layer->elements[index], 
                &layer->elements[index+1],
                (layer->element_count - index - 1) * sizeof(Element));
    }
    
    layer->element_count--;
    layer->dirty = 1;
    smt->dirty = 1;
    smt->total_elements--;
    
    return SMT_SUCCESS;
}

smt_error_t smt_get_root(SMT* smt, unsigned char* root) {
    if (!smt || !root) return SMT_ERROR_NULL_POINTER;
    
    smt_error_t err = update_top_level_root(smt);
    if (err != SMT_SUCCESS) return err;
    
    memcpy(root, smt->top_level_root, HASH_SIZE);
    return SMT_SUCCESS;
}

void smt_print_stats(const SMT* smt) {
    if (!smt) return;
    
    printf("\n=== MerkonDB Statistics ===\n");
    printf("Total Elements: %zu\n", smt->total_elements);
    printf("Active Layers: %d\n", smt->layer_count);
    printf("Max Layers: %d\n", MAX_LAYERS);
    
    int active_layers = 0;
    for (int i = 0; i < smt->layer_count; i++) {
        if (smt->layers[i].element_count > 0) active_layers++;
    }
    printf("Non-empty Layers: %d\n", active_layers);
    
    printf("\nLayer Distribution:\n");
    for (int i = 0; i < smt->layer_count; i++) {
        if (smt->layers[i].element_count > 0) {
            printf("  Layer %d: %d elements\n", i, smt->layers[i].element_count);
        }
    }
    
    unsigned char root[HASH_SIZE];
    SMT* mutable_smt = (SMT*)smt;
    if (smt_get_root(mutable_smt, root) == SMT_SUCCESS) {
        printf("\nTop-level Root: ");
        for (int i = 0; i < HASH_SIZE; i++) printf("%02x", root[i]);
        printf("\n");
    } else {
        printf("\nTop-level Root: <calculation failed>\n");
    }
}