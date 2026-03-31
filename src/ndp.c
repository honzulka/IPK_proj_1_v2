#define _POSIX_C_SOURCE 199309L
#include <stddef.h>
#include <stdint.h>
#include "ndp.h"
#include "iface.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/ethernet.h>
#include "compat.h"
#include <pcap.h>
#include <time.h>

static void ipv6_solicited_node_multicast(const struct in6_addr *target, struct in6_addr *multicast) {
  memset(multicast, 0, sizeof(*multicast));

  multicast->s6_addr[0] = 0xff;
  multicast->s6_addr[1] = 0x02;

  multicast->s6_addr[11] = 0x01;
  multicast->s6_addr[12] = 0xff;

  multicast->s6_addr[13] = target->s6_addr[13];
  multicast->s6_addr[14] = target->s6_addr[14];
  multicast->s6_addr[15] = target->s6_addr[15];
}

static void ipv6_multicast_mac(const struct in6_addr *multicast, uint8_t mac[6]) {
  mac[0] = 0x33;
  mac[1] = 0x33;

  mac[2] = multicast->s6_addr[12];
  mac[3] = multicast->s6_addr[13];
  mac[4] = multicast->s6_addr[14];
  mac[5] = multicast->s6_addr[15];
}

static uint16_t icmpv6_checksum(const struct in6_addr *src, const struct in6_addr *dst, const void *icmp, size_t len) {
  struct {
    struct in6_addr src;
    struct in6_addr dst;
    uint32_t length;
    uint8_t zero[3];
    uint8_t next_header;
  } pseudo;

  memset(&pseudo, 0, sizeof(pseudo));
  pseudo.src = *src;
  pseudo.dst = *dst;
  pseudo.length = htonl(len);
  pseudo.next_header = IPPROTO_ICMPV6;

  uint8_t buf[1500];
  memcpy(buf, &pseudo, sizeof(pseudo));
  memcpy(buf + sizeof(pseudo), icmp, len);

  return checksum(buf, sizeof(pseudo) + len);
}

int scan_single_ndp(pcap_t *handle, const iface_t *iface, const ip_addr_t target_ip, int timeout_ms, ndp_result_t *result) {
  result->ok = 0;
  result->ip = target_ip;

  struct in6_addr multicast;
  uint8_t dst_mac[6];

  ipv6_solicited_node_multicast(&target_ip.ipv6, &multicast);
  ipv6_multicast_mac(&multicast, dst_mac);

  uint8_t packet[128];
  memset(packet, 0, sizeof(packet));

  struct ether_header *eth = (struct ether_header*)packet;
  memcpy(eth->ether_dhost, dst_mac, 6);
  memcpy(eth->ether_shost, iface->mac, 6);
  eth->ether_type = htons(ETH_P_IPV6);

  struct ip6_hdr *ip6 = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
  ip6->ip6_vfc = 0x60;
  ip6->ip6_plen = htons(sizeof(struct nd_neighbor_solicit) + 8);
  ip6->ip6_nxt = IPPROTO_ICMPV6;
  ip6->ip6_hops = 255;

  ip6->ip6_src = iface->ipv6;
  ip6->ip6_dst = multicast;

  struct nd_neighbor_solicit *ns = (struct nd_neighbor_solicit*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));

  ns->nd_ns_type = ND_NEIGHBOR_SOLICIT;
  ns->nd_ns_code = 0;
  ns->nd_ns_reserved = 0;
  ns->nd_ns_target = target_ip.ipv6;

  uint8_t *opt = (uint8_t*)(ns + 1);
  opt[0] = ND_OPT_SOURCE_LINKADDR;
  opt[1] = 1;
  memcpy(opt + 2, iface->mac, 6);

  ns->nd_ns_cksum = 0;
  ns->nd_ns_cksum = icmpv6_checksum(&ip6->ip6_src, &ip6->ip6_dst, ns, sizeof(struct nd_neighbor_solicit) + 8);

  size_t pkt_len = sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_solicit) + 8;

  if (pcap_inject(handle, packet, (int)pkt_len) < 0) {
    return -1;
  }

  int ret, elapsed;
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  struct pcap_pkthdr *hdr;
  const uint8_t *data;

  // flush old packets
  while ((ret = pcap_next_ex(handle, &hdr, &data)) == 1) {
    // ignore any old packets
  }

  while (1) {

     // check timeout
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000;
    if (elapsed >= timeout_ms) {
      result->ok = 0;
      return 0;
    }

    ret = pcap_next_ex(handle, &hdr, &data);
    if (ret == 1) { // packet received
      const struct ether_header *reth = (const struct ether_header*)data;
      if (ntohs(reth->ether_type) != ETH_P_IPV6)
        continue;

      const struct ip6_hdr *rip6 = (const struct ip6_hdr*)(data + sizeof(struct ether_header));

      if (rip6->ip6_nxt != IPPROTO_ICMPV6)
        continue;

      const struct nd_neighbor_advert *na = (const struct nd_neighbor_advert*)(data + sizeof(struct ether_header) + sizeof(struct ip6_hdr));

      if (na->nd_na_type != ND_NEIGHBOR_ADVERT)
        continue;

      if (memcmp(&na->nd_na_target, &target_ip.ipv6, sizeof(struct in6_addr)) != 0)
        continue;

      const uint8_t *opt = (const uint8_t*)(na + 1);

      if (opt[0] == ND_OPT_TARGET_LINKADDR) {
        memcpy(result->mac, opt + 2, 6);
        result->ok = 1;
        return 0;
      }
    } else if (ret == 0) {
      struct timespec ts = {0, NDP_TIMEOUT_LOOP_US * 1000};
      nanosleep(&ts, NULL);
    } else {
      perror("pcap_next_ex");
      return -1;
    }
  }
  return 0;
}
