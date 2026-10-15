/**
 * @file subnet.c
 * @brief CIDR parsing and host iteration implementation.
 */

#include "subnet.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define MAX_IPV6_HOSTS 256

static uint32_t prefix_to_mask(int prefix) {
  if (prefix == 0) return 0;
  return htonl(0xFFFFFFFF << (32 - prefix));
}

static void ipv6_increment(struct in6_addr *addr) {
  for (int i = 15; i >= 0; i--) {
    addr->s6_addr[i]++;
    if (addr->s6_addr[i] != 0)
      break;
  }
}

int parse_subnet(const char *input, subnet_t *subnet) {
  char ip_str[128];
  const char *slash = strchr(input, '/');

  if (!slash) {
    fprintf(stderr, "Invalid subnet: %s\n", input);
    return -1;
  }

  int ip_len = slash - input;
  strncpy(ip_str, input, ip_len);
  ip_str[ip_len] = '\0';

  int prefix = atoi(slash + 1);
  if (prefix < 0 || prefix > 128) {
    fprintf(stderr, "Invalid prefix: %d\n", prefix);
    return -1;
  }

  memset(subnet, 0, sizeof(*subnet));
  subnet->prefix = prefix;

  // --- IPv4 ---
  struct in_addr addr4;
  if (inet_pton(AF_INET, ip_str, &addr4) == 1) {

    if (prefix > 32) {
      fprintf(stderr, "Invalid IPv4 prefix: %d\n", prefix);
      return -1;
    }

    subnet->family = AF_INET;

    uint32_t ip = ntohl(addr4.s_addr);
    uint32_t mask = ntohl(prefix_to_mask(prefix));

    uint32_t network = ip & mask;
    uint32_t broadcast = network | ~mask;

    subnet->v4.network.s_addr = htonl(network);
    subnet->v4.mask.s_addr = htonl(mask);

    if (prefix == 32) {
      subnet->v4.current = subnet->v4.network;
      subnet->host_count = 1;

    } else if (prefix == 31) {
      subnet->v4.current.s_addr = htonl(network);
      subnet->host_count = 2;

    } else {
      subnet->v4.current.s_addr = htonl(network + 1);
      subnet->host_count = broadcast - network - 1;
    }

    subnet->generated = 0;
    return 0;
  }

  // --- IPv6 ---
  struct in6_addr addr6;
  if (inet_pton(AF_INET6, ip_str, &addr6) == 1) {

    subnet->family = AF_INET6;
    subnet->v6.network = addr6;
    subnet->v6.current = addr6;

    int bits = 128 - prefix;

    if (bits >= 64) {
      subnet->host_count = MAX_IPV6_HOSTS;
    } else {
      uint64_t count = 1ULL << bits;
      subnet->host_count =
        count > MAX_IPV6_HOSTS ? MAX_IPV6_HOSTS : count;
    }

    subnet->generated = 0;
    return 0;
  }

  fprintf(stderr, "Invalid IP address: %s\n", ip_str);
  return -1;
}

int subnet_next_ip(subnet_t *subnet, ip_addr_t *ip) {

  if (subnet->generated >= subnet->host_count)
    return 0;

  if (subnet->family == AF_INET) {

    ip->family = AF_INET;
    ip->ipv4 = subnet->v4.current;

    uint32_t next = ntohl(subnet->v4.current.s_addr) + 1;
    subnet->v4.current.s_addr = htonl(next);

  } else if (subnet->family == AF_INET6) {

    ip->family = AF_INET6;
    ip->ipv6 = subnet->v6.current;

    ipv6_increment(&subnet->v6.current);

  } else {
    return 0;
  }

  subnet->generated++;
  return 1;
}

void ip_to_str(const ip_addr_t *ip, char *buffer, size_t size) {
  if (ip->family == AF_INET) {
    inet_ntop(AF_INET, &ip->ipv4, buffer, size);
  } else {
    inet_ntop(AF_INET6, &ip->ipv6, buffer, size);
  }
}
