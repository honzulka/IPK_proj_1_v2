#ifndef SUBNET_H
#define SUBNET_H

#include <stdint.h>
#include <netinet/in.h>
#include "iface.h"

#define MAX_IPV6_HOSTS 256

typedef struct {
  int family;
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

int parse_subnet(const char *input, subnet_t *subnet);
int subnet_next_ip(subnet_t *subnet, ip_addr_t *ip);
void ip_to_str(const ip_addr_t *ip, char *buffer, size_t size);

#endif
