/**
 * @file ndp.h
 * @brief IPv6 Neighbor Discovery (Neighbor Solicitation/Advertisement) scan.
 */

#ifndef NDP_H
#define NDP_H

#include <stdint.h>
#include <netinet/in.h>
#include "iface.h"
#include "compat.h"
#include <pcap.h>

#define ICMPV6_NEIGHBOR_SOLICIT 135
#define ICMPV6_NEIGHBOR_ADVERT  136

#define NDP_OPT_SOURCE_LLADDR   1
#define NDP_OPT_TARGET_LLADDR   2

#define NDP_NA_FLAG_ROUTER    0x80000000
#define NDP_NA_FLAG_SOLICITED 0x40000000
#define NDP_NA_FLAG_OVERRIDE  0x20000000

#define NDP_TIMEOUT_LOOP_US 1000

typedef struct {
  ip_addr_t ip;
  uint8_t mac[6];
  int ok;
} ndp_result_t;

/*
 * ICMPv6 Neighbor Solicitation
 */
typedef struct {
  uint8_t  type;
  uint8_t  code;
  uint16_t checksum;
  uint32_t reserved;
  struct in6_addr target;
} __attribute__((packed)) ndp_ns_t;

/*
 * ICMPv6 Neighbor Advertisement
 */
typedef struct {
  uint8_t  type;
  uint8_t  code;
  uint16_t checksum;
  uint32_t flags;
  struct in6_addr target;
} __attribute__((packed)) ndp_na_t;

/*
 * NDP option header
 */
typedef struct {
  uint8_t type;
  uint8_t length;
} __attribute__((packed)) ndp_opt_t;

/*
 * Source / Target Link-Layer option
 */
typedef struct {
  uint8_t type;
  uint8_t length;
  uint8_t mac[6];
} __attribute__((packed)) ndp_opt_lladdr_t;

/**
 * @brief Send NDP Neighbor Solicitation and wait for Neighbor Advertisement.
 *
 * @param handle libpcap capture handle (used for both inject and capture).
 * @param iface Source interface info (MAC + IPv6 required).
 * @param target_ip Target IPv6 address (ip.family must be AF_INET6).
 * @param timeout_ms Timeout in milliseconds.
 * @param result Output result.
 * @return 0 on success (even if no reply), -1 on fatal error.
 */
int scan_single_ndp(pcap_t *handle, const iface_t *iface, const ip_addr_t target_ip, int timeout_ms, ndp_result_t *result);

#endif
