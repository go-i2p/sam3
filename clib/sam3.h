#ifndef SAM3_H
#define SAM3_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Concrete structure definitions */
struct sam3_context_t {
    void* go_ctx;
};

struct sam3_keys_t {
    void* go_keys;
};

struct sam3_session_t {
    void* go_session;
};

struct sam3_stream_t {
    void* go_stream;
};

typedef struct sam3_context_t sam3_context_t;
typedef struct sam3_keys_t sam3_keys_t;
typedef struct sam3_session_t sam3_session_t;
typedef struct sam3_stream_t sam3_stream_t;

/* Error codes */
typedef enum {
    SAM3_SUCCESS = 0,
    SAM3_ERROR_INVALID_PARAM = -1,
    SAM3_ERROR_CONNECTION = -2, 
    SAM3_ERROR_MEMORY = -3,
    SAM3_ERROR_KEYS = -4,
    SAM3_ERROR_SESSION = -5
} sam3_error_t;

/* Log levels */
typedef enum {
    SAM3_LOG_ERROR = 0,
    SAM3_LOG_WARN = 1,
    SAM3_LOG_DEBUG = 2
} sam3_log_level_t;

/* Initialize SAM3 library context
 * @param address SAM bridge address (e.g. "127.0.0.1:7656")
 * @return context handle on success, NULL on failure 
 */
sam3_context_t* sam3_init(const char* address);

/* Free SAM3 library context
 * @param ctx Context to free
 */
void sam3_cleanup(sam3_context_t* ctx);

/* Generate new I2P keys
 * @param ctx SAM3 context
 * @return keys handle on success, NULL on failure
 */
sam3_keys_t* sam3_generate_keys(sam3_context_t* ctx);

/* Free I2P keys
 * @param keys Keys to free
 */
void sam3_free_keys(sam3_keys_t* keys);

/* Create stream session
 * @param ctx SAM3 context
 * @param name Session name
 * @param keys Keys to use
 * @return session handle on success, NULL on failure
 */
sam3_session_t* sam3_stream_session(sam3_context_t* ctx, 
                                  const char* name,
                                  sam3_keys_t* keys);

/* Free session
 * @param session Session to free
 */
void sam3_close_session(sam3_session_t* session);

/* Get last error message
 * @return Error message string, valid until next API call
 */ 
const char* sam3_last_error(void);

/* Set log level
 * @param level New log level
 */
void sam3_set_log_level(sam3_log_level_t level);

#ifdef __cplusplus
}
#endif

#endif /* SAM3_H */