#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>
#include "iface.h"

typedef struct {
  ip_addr_t ip;
  int ok;
} icmp_result_t;

int scan_single_icmp(ip_addr_t target_ip, int timeout_ms, icmp_result_t *res);

#endif
