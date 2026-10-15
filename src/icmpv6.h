/**
 * @file icmpv6.h
 * @brief ICMPv6 echo scan (sent on Ethernet via libpcap injection).
 */

#ifndef ICMPV6_H
#define ICMPV6_H

#include <stdint.h>
#include "iface.h"
#include "compat.h"
#include <pcap.h>

#define NDP_TIMEOUT_LOOP_US 1000

typedef struct {
  ip_addr_t ip;
  int ok;
} icmpv6_result_t;

/**
 * @brief Send a single ICMPv6 echo request and wait for an echo reply.
 *
 * Requires destination MAC address (typically obtained by NDP).
 *
 * @param handle libpcap handle used for injection and capture.
 * @param target Target IPv6 address.
 * @param timeout_ms Timeout in milliseconds.
 * @param result Output result.
 * @param iface Source interface info (MAC + IPv6 required).
 * @param dst_mac Destination MAC address to use in Ethernet header.
 * @return 0 on success (even if no reply), -1 on fatal error.
 */
int scan_single_icmpv6(pcap_t *handle, const ip_addr_t *target, int timeout_ms, icmpv6_result_t *result, const iface_t *iface, const uint8_t dst_mac[6]);

#endif
