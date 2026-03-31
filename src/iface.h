#ifndef IFACE_H
#define IFACE_H

#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>

typedef struct {
  int family; // AF_INET or AF_INET6
  union {
    struct in_addr ipv4;
    struct in6_addr ipv6;
  };
} ip_addr_t;


typedef struct {
  char name[IF_NAMESIZE];
  uint8_t mac[6];
  struct in_addr ipv4;
  int has_ipv4;
  struct in6_addr ipv6;
  int has_ipv6;
} iface_t;

int list_interfaces(void);
int get_interface_info(const char *ifname, iface_t *iface);

#endif
