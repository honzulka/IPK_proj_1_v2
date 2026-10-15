/**
 * @file icmpv6.c
 * @brief Reliable ICMPv6 echo scanning via raw Ethernet frames (pcap_inject).
 */

#define _POSIX_C_SOURCE 199309L
#include "icmpv6.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/ethernet.h>
#include <time.h>
#include "compat.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

static uint16_t icmpv6_checksum(const struct in6_addr *src, const struct in6_addr *dst,
                                const void *icmp, size_t len) {
  struct {
    struct in6_addr src;
    struct in6_addr dst;
    uint32_t length;
    uint8_t zero[3];
    uint8_t next;
  } pseudo;

  memset(&pseudo, 0, sizeof(pseudo));
  pseudo.src = *src;
  pseudo.dst = *dst;
  pseudo.length = htonl(len);
  pseudo.next = IPPROTO_ICMPV6;

  uint8_t buf[1500];
  memcpy(buf, &pseudo, sizeof(pseudo));
  memcpy(buf + sizeof(pseudo), icmp, len);

  return checksum(buf, sizeof(pseudo) + len);
}

int scan_single_icmpv6(pcap_t *handle, const ip_addr_t *target, int timeout_ms,
                       icmpv6_result_t *result, const iface_t *iface, const uint8_t dst_mac[6]) {
  result->ok = 0;
  result->ip = *target;

  // flush old packets
  struct pcap_pkthdr *hdr;
  const uint8_t *data;
  while (pcap_next_ex(handle, &hdr, &data) == 1) { }

  // BPF filter pro ICMPv6 pouze od cílové adresy
  struct bpf_program fp;
  char ipbuf[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &iface->ipv6, ipbuf, sizeof(ipbuf));
  char filter_exp[128];
  snprintf(filter_exp, sizeof(filter_exp), "icmp6 and ip6 dst %s", ipbuf);
  if (pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) < 0 ||
      pcap_setfilter(handle, &fp) < 0) {
    perror("pcap filter");
    return -1;
  }

  // sestavení paketu
  uint8_t packet[128];
  memset(packet, 0, sizeof(packet));
  struct ether_header *eth = (struct ether_header*)packet;
  memcpy(eth->ether_dhost, dst_mac, 6);
  memcpy(eth->ether_shost, iface->mac, 6);
  eth->ether_type = htons(ETH_P_IPV6);

  struct ip6_hdr *ip6 = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
  ip6->ip6_vfc = 0x60;
  ip6->ip6_plen = htons(sizeof(struct icmp6_hdr));
  ip6->ip6_nxt = IPPROTO_ICMPV6;
  ip6->ip6_hops = 64;
  ip6->ip6_src = iface->ipv6;
  ip6->ip6_dst = target->ipv6;

  struct icmp6_hdr *icmp = (struct icmp6_hdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
  icmp->icmp6_type = ICMP6_ECHO_REQUEST;
  icmp->icmp6_code = 0;
  icmp->icmp6_id = htons(0x1234); // optional, can randomize
  icmp->icmp6_seq = htons(0);
  icmp->icmp6_cksum = 0;
  icmp->icmp6_cksum = icmpv6_checksum(&ip6->ip6_src, &ip6->ip6_dst, icmp, sizeof(struct icmp6_hdr));

  size_t pkt_len = sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
  if (pcap_inject(handle, packet, (int)pkt_len) < 0) return -1;

  struct timespec start, now;
  clock_gettime(CLOCK_MONOTONIC, &start);

  while (1) {
    clock_gettime(CLOCK_MONOTONIC, &now);
    int elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec)/1000000;
    if (elapsed >= timeout_ms) return 0;

    int ret = pcap_next_ex(handle, &hdr, &data);
    if (ret != 1) {
      struct timespec ts = {0, 1000*100}; // 100 us sleep
      nanosleep(&ts, NULL);
      continue;
    }

    const struct ether_header *reth = (const struct ether_header*)data;
    if (ntohs(reth->ether_type) != ETH_P_IPV6) continue;

    const struct ip6_hdr *rip6 = (const struct ip6_hdr*)(data + sizeof(struct ether_header));
    if (rip6->ip6_nxt != IPPROTO_ICMPV6) continue;

    const struct icmp6_hdr *ricmp = (const struct icmp6_hdr*)(data + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
    if (ricmp->icmp6_type != ICMP6_ECHO_REPLY) continue;

    result->ok = 1;
    return 0;
  }
}
