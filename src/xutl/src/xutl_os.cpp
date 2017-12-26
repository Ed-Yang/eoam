#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> /* close */
#include <string.h>
#include <stdint.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#ifdef __APPLE__
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <sys/sysctl.h>
#else
#include <sys/ioctl.h>
#include <linux/if.h>
#include <sys/sysinfo.h>
#endif

#include <pcap.h>
#include "xutl_os.h"

#define MAC_ADDRESS_SIZE    6

#ifdef __APPLE__

char *xos_eth_dev(void)
{
    static char *dev = (char *)"en0";

    return dev;
}

uint32_t xos_get_uptime()
{
    struct timeval boottime;
    size_t len = sizeof(boottime);
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    if( sysctl(mib, 2, &boottime, &len, NULL, 0) < 0 )
    {
        return 0;
    }
    time_t bsec = boottime.tv_sec, csec = time(NULL);

    return difftime(csec, bsec);
}

int xos_get_mac(char *dev, char *mac)
{
    struct ifaddrs *if_addrs = NULL;
    struct ifaddrs *if_addr = NULL;
    int found = 0;

    if (getifaddrs(&if_addrs) != 0)
    {
        return -1;
    }

    for (if_addr = if_addrs; if_addr != NULL && found == 0;
         if_addr = if_addr->ifa_next)
    {
        if (if_addr->ifa_addr != NULL &&
            if_addr->ifa_addr->sa_family == AF_LINK &&
            strcmp(dev, if_addr->ifa_name) == 0)
        {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)if_addr->ifa_addr;

            if (6 == sdl->sdl_alen)
            {
                memcpy(mac, LLADDR(sdl), sdl->sdl_alen);
                found = 1;
                break;
            }
        }
    }

    if (if_addrs)
        free(if_addrs);

    return found;
}

int get_sys_mac(char *dev, uint8_t *mac)
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    pcap_addr_t *alladdrs;
    pcap_addr_t *a;
    struct sockaddr_dl* link;
    char eb[PCAP_ERRBUF_SIZE];
    int found = 0;

    if (pcap_findalldevs(&alldevs, eb) == -1)
    {
        return -1;
    }

    for (d = alldevs; d != NULL && found == 0; d = d->next)
    {
        if (strcmp(dev, d->name) != 0)
            continue;

        alladdrs = d->addresses;

        for (a = alladdrs; a != NULL && found == 0; a = a->next)
        {
            if(a->addr->sa_family == AF_LINK)
            {
                link = (struct sockaddr_dl*)a->addr;
                memcpy(mac, LLADDR(link), link->sdl_alen);
                found = 1;
            }
        }
    }

    return 0;
}

#else

char *xos_eth_dev(void)
{
    static char *dev = (char *)"eth0";

    return dev;
}

uint32_t xos_get_uptime()
{
    struct sysinfo s_info;

    if(sysinfo(&s_info) != 0)
    {
        perror("sysinfo");
    }

    return s_info.uptime;
}

int xos_get_mac(char *dev, char *mac)
{
    int sockfd;
    struct ifreq s;
    int retval = -1;

    sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, dev);
    if (0 == ioctl(sockfd, SIOCGIFHWADDR, &s))
    {
        memcpy(mac, s.ifr_addr.sa_data, MAC_ADDRESS_SIZE);
        retval = 0;
    }

    close(sockfd);

    return retval;
}
#endif


void xos_delay(uint32_t msec)
{
    struct timeval tv;

    tv.tv_sec = msec / 1000;
    tv.tv_usec = (msec % 1000) / 1000;

    select(FD_SETSIZE, NULL, NULL, NULL, &tv);
}
