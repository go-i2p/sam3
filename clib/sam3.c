#include "sam3.h"
#include "_cgo_export.h"
#include <stdlib.h>
#include <string.h>

/* Thread-local error buffer */
static __thread char error_buf[1024];

static void set_error(const char* msg) {
    strncpy(error_buf, msg, sizeof(error_buf) - 1);
    error_buf[sizeof(error_buf) - 1] = '\0';
}

sam3_context_t* sam3_init(const char* address) {
    if (!address) {
        set_error("Invalid address parameter");
        return NULL;
    }

    sam3_context_t* ctx = malloc(sizeof(struct sam3_context_t));
    if (!ctx) {
        set_error("Out of memory");
        return NULL;
    }

    // Create a non-const copy for the Go function
    char* addr_copy = strdup(address);
    if (!addr_copy) {
        free(ctx);
        set_error("Out of memory");
        return NULL;
    }

    void* go_ctx = GoSam3Init(addr_copy);
    free(addr_copy);

    if (!go_ctx) {
        free(ctx);
        set_error("Failed to initialize SAM connection");
        return NULL;
    }

    ctx->go_ctx = go_ctx;
    return ctx;
}

void sam3_cleanup(sam3_context_t* ctx) {
    if (ctx) {
        GoSam3Cleanup(ctx->go_ctx);
        free(ctx);
    }
}

sam3_keys_t* sam3_generate_keys(sam3_context_t* ctx) {
    if (!ctx) {
        set_error("Invalid context");
        return NULL;
    }

    sam3_keys_t* keys = malloc(sizeof(struct sam3_keys_t));
    if (!keys) {
        set_error("Out of memory");
        return NULL;
    }

    void* go_keys = GoSam3GenerateKeys(ctx->go_ctx);
    if (!go_keys) {
        free(keys);
        set_error("Failed to generate keys");
        return NULL;
    }

    keys->go_keys = go_keys;
    return keys;
}
