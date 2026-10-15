/**
 * @file iface.h
 * @brief Network interface discovery and basic address types.
 */


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


/**
 * @brief Print active interfaces.
 * @return 0 on success, -1 on error.
 */
int list_interfaces(void);

/**
 * @brief Fill @ref iface_t for a given interface name.
 *
 * @param ifname Interface name (e.g., "eth0").
 * @param iface Output structure.
 * @return 0 on success, -1 on error.
 */
int get_interface_info(const char *ifname, iface_t *iface);

#endif
