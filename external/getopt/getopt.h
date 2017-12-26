#ifndef _GETOPT_H_
#define _GETOPT_H_ 1

#if 1 /* edward, port */
#define NETSNMP_IMPORT
#else
#ifndef NET_SNMP_CONFIG_H
#error <net-snmp/net-snmp-config.h> must be included before <net-snmp/library/getopt.h>.
#endif
#endif

#if !defined(HAVE_GETOPT_H)

#ifdef __cplusplus
extern          "C" {
#endif

NETSNMP_IMPORT int   getopt(int, char *const *, const char *);
NETSNMP_IMPORT char *optarg;
NETSNMP_IMPORT int   optind, opterr, optopt, optreset;

#ifdef __cplusplus
}
#endif

#endif /* HAVE_GETOPT_H */

#endif
