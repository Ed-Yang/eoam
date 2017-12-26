#include <stdlib.h> /* malloc */

#ifndef __XUTL_MEM_H
#define __XUTL_MEM_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef NO_DBG_MEM

    #ifndef xmem_malloc
    #define xmem_malloc(size) malloc(size)
    #endif

    #ifndef xmem_free
    #define xmem_free(ptr,size) free(ptr)
    #endif

#else
    void *xmem_malloc(int size);
    void xmem_free(void *ptr, int size);
#endif



#ifdef __cplusplus
}
#endif

#endif /* __XUTL_MEM_H */


