#include <stdio.h>
#include <stdint.h>

#ifndef __XUTL_BITS_H
#define __XUTL_BITS_H

#ifdef __cplusplus
extern "C" {
#endif

#define XBITS_SET_BIT(p, n)     ((p) |= (1) << (n))
#define XBITS_CLR_BIT(p, n)     ((p) &= ~((1) << (n)))
#define XBITS_FLIP_BIT(p,n)     ((p) ^= (1 << (n)))
#define XBITS_CHECK_BIT(p,n)    ((p) & (1 << (n)))

#define XBITS_CLR_MASK(p, m)    ((p) &= ~(m))
#define XBITS_FLIP_MASK(p, m)   ((p) ^= (m))

#define XBITS_OR_V(x, v)        ((x) |= (v)) /* or */
#define XBITS_SET_V(x, m, v)    ((x) = ((x) & (~m)) | ((v) & (m)))
#define XBITS_CLR_V(x, v)       ((x) &= (~(v)))
#define XBITS_CHECK_V(x, v)     (((x) & (v)) == (v))

#ifdef __cplusplus
}
#endif

#endif /* __XUTL_BITS_H */

