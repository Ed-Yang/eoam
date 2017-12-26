#include <stdio.h>
#include <stdint.h>

#include "xutl_str.h"

int xstr_hex2bin(uint8_t *dst_bin, const char *hexstr, size_t hsize)
{
    unsigned char h, l;
    uint8_t *ptr = (uint8_t *)hexstr;
    int i;
    size_t bsize;

    bsize = hsize / 2;

    for (i = 0; i < (int)bsize; i++)
    {
        h = (*ptr >= 'a') ? (*ptr - 'a') + 10 : (*ptr - '0'); ptr++;
        l = (*ptr >= 'a') ? (*ptr - 'a') + 10 : (*ptr - '0'); ptr++;

        dst_bin[i] = (h << 4) | (l & 0x0f);
    }

    return (int)bsize;
}

char *xstr_bin2hex(char *dst_hex, const uint8_t *bin, size_t bsize)
{
    unsigned char h, l;
    size_t i;

    for (i = 0; i < bsize; i++)
    {
        h = (bin[i] & 0xf0) >> 4;
        l = bin[i] & 0x0f;

        dst_hex[i * 2] = (h >= 10) ? (h - 10) + 'a' : h + '0';
        dst_hex[i * 2 + 1] = (l >= 10) ? (l - 10) + 'a' : l + '0';
    }

    return (char *)dst_hex;
}

void xstr_dump(const uint8_t *bin, size_t bsize, size_t column)
{
    size_t i;
    size_t col = column;

    if (col == 0)
        col = 32;

    printf("\n\n");

    for (i = 0; i < bsize; i++)
    {
#if 0
        if (bin[i] == 0xcc)
        {
            printf("*"); 
        }
#endif

        if ((i % 4) == 3)
        {
            printf("%02x ", (uint8_t)bin[i]);
        }
        else
        {
            printf("%02x", (uint8_t)bin[i]);
        }

        if (((i + 1) % col) == 0)
        {
            printf("\n");
        }
    }

    fflush(stdout);
}

int xstr_ipstr(char *ip_str, int buf_size, const char *ip)
{
    int n;

    n = snprintf(ip_str, buf_size, "%-u.%-u.%-u.%u", ip[0], ip[1], ip[2], ip[3]);

    return n;
}

