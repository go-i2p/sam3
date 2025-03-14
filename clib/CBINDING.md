# Memory Management in SAM3 C Bindings

## General Rules
- Every `sam3_init()` call must be matched with `sam3_cleanup()`
- Every `sam3_generate_keys()` call must be matched with `sam3_free_keys()`
- Every successful session creation must be matched with `sam3_close_session()`
- Handles (context, keys, session) are invalid after their free function is called
- Never pass NULL pointers to API functions unless explicitly documented
- Error messages are valid only until next API call

## Ownership Rules
- The library owns all internal resources
- The application owns all handles returned by API functions
- The application must not access freed handles
- String parameters are copied by the library
- String returns are owned by the library

## Thread Safety
- Context handles are not thread safe
- Each thread should use its own context
- Error messages are thread-local