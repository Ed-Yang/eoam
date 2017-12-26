#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#ifndef __XUTL_DEFS_H
#define __XUTL_DEFS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef TRUE
#define TRUE        1
#endif

#ifndef FALSE
#define FALSE       0
#endif

#ifndef BOOLEAN
typedef unsigned char BOOLEAN;
#endif

#define XUTL_NAME_SIZE      64
#define XUTL_FRAME_SIZE     1518 /* maximum ethernet frame size */

typedef enum
{
    MIB_TRUE = 1,
    MIB_FALSE
} mib_truth_e; /* RFC 2579 */

typedef struct
{
    uint32_t low;
    uint32_t high;
} mib_cnt64_s;

typedef uint32_t ifindex_s;

#ifdef __cplusplus
}
#endif

#endif /* __XUTL_DEFS_H */
