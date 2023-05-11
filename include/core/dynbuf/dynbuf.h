#ifndef _DYNAMICBUF_H
#define _DYNAMICBUF_H
#include <stdint.h>

/**
 * Structure describing the parameters of a mbuf dynamic field.
 */
#define DYN_NAMESIZE 64
struct dyn_field_cfg {
    char name[DYN_NAMESIZE];
    uint32_t offset;
    uint8_t aligned;
    uint32_t register_size;
};

/**
 * Shared data at the end of an external buffer.
 */
struct dyn_ext_shared_info {
    void *fcb;
};

template <typename NestedClass>
struct dyn_buf {
    NestedClass instance;
    uint32_t ex_size;
    union {
        char freecb[0];
        struct dyn_ext_shared_info* shared_info;
    };
};

int dynfield_register();


#endif // _DYNAMICBUF_H