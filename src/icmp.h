/**
 * @file icmp.h
 * @brief ICMPv4 echo scan.
 */

#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>
#include "iface.h"

typedef struct {
  ip_addr_t ip;
  int ok;
} icmp_result_t;

/**
 * @brief Send ICMP echo request and wait for a reply until timeout.
 *
 * @param iface Source interface info.
 * @param target_ip Target IPv4 address (ip.family must be AF_INET).
 * @param timeout_ms Timeout in milliseconds.
 * @param res Output result.
 * @return 0 on success (even if host did not respond), -1 on fatal error.
 */
int scan_single_icmp(const iface_t *iface, ip_addr_t target_ip, int timeout_ms, icmp_result_t *res);

#endif
