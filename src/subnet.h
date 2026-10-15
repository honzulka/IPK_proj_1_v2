/**
 * @file subnet.h
 * @brief Parsing and iteration over IPv4/IPv6 CIDR ranges.
 */

#ifndef SUBNET_H
#define SUBNET_H

#include <stdint.h>
#include <netinet/in.h>
#include "iface.h"

#define MAX_IPV6_HOSTS 256

typedef struct {
  int family; // AF_INET or AF_INET6
  int prefix;

  uint64_t host_count;
  uint64_t generated;

  union {
    struct {
      struct in_addr network;
      struct in_addr mask;
      struct in_addr current;
    } v4;

    struct {
      struct in6_addr network;
      struct in6_addr current;
    } v6;
  };
} subnet_t;

/**
 * @brief Parse subnet in CIDR form
 *
 * @param input Subnet string.
 * @param subnet Output structure.
 * @return 0 on success, -1 on parse/validation error.
 */
int parse_subnet(const char *input, subnet_t *subnet);


/**
 * @brief Generate next host IP from the subnet iterator.
 *
 * @param subnet Subnet iterator state.
 * @param ip Output IP.
 * @return 1 if a new host was produced, 0 if finished/unsupported family.
 */
int subnet_next_ip(subnet_t *subnet, ip_addr_t *ip);

/**
 * @brief Convert @ref ip_addr_t to printable string.
 *
 * @param ip Input address.
 * @param buffer Output buffer.
 * @param size Buffer size.
 */
void ip_to_str(const ip_addr_t *ip, char *buffer, size_t size);

#endif
