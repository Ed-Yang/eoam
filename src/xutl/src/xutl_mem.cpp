#include <stdint.h>
#include <stdlib.h>
#include <xutl_mem.h>

void *xmem_malloc(int size)
{
    return malloc(size);
} 

void xmem_free(void *ptr, int size)
{
    if (size) {}
    
    free(ptr);
}
