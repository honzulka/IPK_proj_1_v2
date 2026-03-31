#ifndef ICMPV6_H
#define ICMPV6_H

#include <stdint.h>
#include "iface.h"
#include "compat.h"
#include <pcap.h>

typedef struct {
  ip_addr_t ip;
  int ok;
} icmpv6_result_t;

int scan_single_icmpv6(pcap_t *handle, const ip_addr_t *target, int timeout_ms, icmpv6_result_t *result, const iface_t *iface, uint8_t dst_mac[6]);

#endif
