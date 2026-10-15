/**
 * @file arp.h
 * @brief ARP scan for IPv4 hosts (MAC resolution).
 */

#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include "compat.h"
#include <pcap.h>
#include "iface.h"
#include <net/ethernet.h>

struct arp_packet {
  struct ethhdr eth;
  struct {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
  } arp;
} __attribute__((packed));

typedef struct {
  ip_addr_t ip;
  uint8_t mac[6];
  int ok;
} arp_result_t;

/**
 * @brief Send ARP request and wait for ARP reply for the target.
 *
 * @param handle libpcap capture handle for receiving frames.
 * @param iface Source interface info (MAC + IPv4 required).
 * @param target_ip Target IPv4 address (ip.family must be AF_INET).
 * @param timeout_ms Timeout in milliseconds.
 * @param res Output result.
 * @return 0 on success (even if no reply), -1 on fatal error.
 */
int scan_single_arp(pcap_t *handle, const iface_t *iface, ip_addr_t target_ip, int timeout_ms, arp_result_t *res);

#endif
