/**
 * @file main.c
 * @brief Entry point and scan orchestration (ARP/ICMPv4 + NDP/ICMPv6).
 *
 * The tool iterates over given subnets and for each host performs:
 * - IPv4: ARP + ICMP echo
 * - IPv6: NDP + ICMPv6 echo (only if NDP succeeded)
 */

#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include "args.h"
#include "icmp.h"
#include "iface.h"
#include "ndp.h"
#include "subnet.h"
#include "arp.h"
#include "icmpv6.h"

int main(int argc, char **argv) {
  args_t args;

  if (parse_args(argc, argv, &args) != 0) {
    print_usage();
    return -1;
  }

  if (args.help) {
    print_usage();
    return 0;
  }

  if (args.list_interfaces) {
    list_interfaces();
    return 0;
  }

  iface_t iface;
  if (get_interface_info(args.interface, &iface) != 0) {
    return -1;
  }

  // --- print all subnet headers first ---
  printf("Scanning ranges:\n");
  for (int i = 0; i < args.subnet_count; i++) {
    subnet_t s;
    if (parse_subnet(args.subnets[i], &s) != 0)
      continue;

    ip_addr_t net_ip;
    char net_str[INET6_ADDRSTRLEN];

    if (s.family == AF_INET) {
      net_ip.family = AF_INET;
      net_ip.ipv4 = s.v4.network;
    } else {
      net_ip.family = AF_INET6;
      net_ip.ipv6 = s.v6.network;
    }

    ip_to_str(&net_ip, net_str, sizeof(net_str));
    printf("%s/%d %lu\n", net_str, s.prefix, s.host_count);
  }
  printf("\n");  // empty line before host results

  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];

  handle = pcap_open_live(iface.name, 65536, 1, args.timeout_ms, errbuf);
  if (!handle) {
    fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
    return -1;
  }

  // set non-blocking mode to avoid blocking on flush
  if (pcap_setnonblock(handle, 1, errbuf) < 0) {
    fprintf(stderr, "pcap_setnonblock failed: %s\n", errbuf);
    pcap_close(handle);
    return -1;
  }

  for (int i = 0; i < args.subnet_count; i++) {
    subnet_t s;
    ip_addr_t ip;
    if (parse_subnet(args.subnets[i], &s) != 0)
      continue;

    if (s.family == AF_INET) { // IPv4
 
      arp_result_t arp_res;
      icmp_result_t icmp_res;

      while (subnet_next_ip(&s, &ip)) {
        char ip_str[INET_ADDRSTRLEN];
        ip_to_str(&ip, ip_str, sizeof(ip_str));

        arp_res.ip = ip;

        if (scan_single_arp(handle, &iface, ip, args.timeout_ms, &arp_res) != 0) {
          pcap_close(handle);
          return -1;
        }

        if (arp_res.ok) {
          printf("%s arp OK (%02x-%02x-%02x-%02x-%02x-%02x), ", ip_str,
                arp_res.mac[0], arp_res.mac[1], arp_res.mac[2], arp_res.mac[3], arp_res.mac[4], arp_res.mac[5]);
        } else {
          printf("%s arp FAIL, ", ip_str);
        }

        icmp_res.ip = ip;

        if (scan_single_icmp(&iface, ip, args.timeout_ms, &icmp_res) != 0) {
          pcap_close(handle);
          return -1;
        }

        if (icmp_res.ok) {
          printf("icmpv4 OK\n");
        } else {
          printf("icmpv4 FAIL\n");
        }
      }
    } else if (s.family == AF_INET6) { // IPv6

      ndp_result_t ndp_res;
      icmpv6_result_t icmpv6_res;

      while (subnet_next_ip(&s, &ip)) {
        char ip_str[INET6_ADDRSTRLEN];
        ip_to_str(&ip, ip_str, sizeof(ip_str));

        ndp_res.ip = ip;

        if(scan_single_ndp(handle, &iface, ip, args.timeout_ms, &ndp_res) != 0) {
          pcap_close(handle);
          return -1;
        }

        if (ndp_res.ok) {
          printf("%s ndp OK (%02x-%02x-%02x-%02x-%02x-%02x), ", ip_str,
                ndp_res.mac[0], ndp_res.mac[1], ndp_res.mac[2], ndp_res.mac[3], ndp_res.mac[4], ndp_res.mac[5]);
        } else {
          printf("%s ndp FAIL, icmpv6 FAIL\n", ip_str);
          continue; // skip ICMPv6 (ndp failed)
        }
 
        icmpv6_res.ip = ip;

        if (scan_single_icmpv6(handle, &ip, args.timeout_ms, &icmpv6_res, &iface, ndp_res.mac) != 0) {
          pcap_close(handle);
          return -1;
        }

        if (icmpv6_res.ok) {
          printf("icmpv6 OK\n");
        } else {
          printf("icmpv6 FAIL\n");
        }
      }
    } else {
      pcap_close(handle);
      return -1;
    }
  }
  pcap_close(handle);
  return 0;
}
