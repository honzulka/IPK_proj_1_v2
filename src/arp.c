/**
 * @file arp.c
 * @brief ARP request sending and reply matching via libpcap.
 */

#define _POSIX_C_SOURCE 199309L
#include "arp.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <time.h>

static int send_arp_request(const iface_t *iface, ip_addr_t target_ip) {
  int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
  if (sock < 0) {
    perror("socket");
    return -1;
  }

  struct arp_packet pkt;
  memset(&pkt, 0, sizeof(pkt));

  // Ethernet header
  memset(pkt.eth.h_dest, 0xff, 6); // broadcast
  memcpy(pkt.eth.h_source, iface->mac, 6);
  pkt.eth.h_proto = htons(ETH_P_ARP);

  // ARP header
  pkt.arp.htype = htons(1);             // Ethernet
  pkt.arp.ptype = htons(ETH_P_IP);      // IPv4
  pkt.arp.hlen = 6;
  pkt.arp.plen = 4;
  pkt.arp.oper = htons(1);              // request

  memcpy(pkt.arp.sha, iface->mac, 6);

  // Source IP
  memcpy(pkt.arp.spa, &iface->ipv4.s_addr, 4);
  
  memset(pkt.arp.tha, 0x00, 6);         // unknown target MAC
  memcpy(pkt.arp.tpa, &target_ip.ipv4.s_addr, 4);

  // Socket address
  struct sockaddr_ll addr;
  memset(&addr, 0, sizeof(addr));
  addr.sll_family = AF_PACKET;
  addr.sll_ifindex = if_nametoindex(iface->name);
  addr.sll_halen = ETH_ALEN;
  memset(addr.sll_addr, 0xff, 6); // broadcast

  int ret = sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr*)&addr, sizeof(addr));

  if (ret < 0) {
    perror("sendto");
    close(sock);
    return -1;
  }

  close(sock);
  return 0;
}

int scan_single_arp(pcap_t *handle, const iface_t *iface, ip_addr_t target_ip, int timeout_ms, arp_result_t *res) {
  struct pcap_pkthdr *hdr;
  const uint8_t *packet;
  int ret;
  int elapsed = 0;

  // flush old packets
  while ((ret = pcap_next_ex(handle, &hdr, &packet)) == 1) {
    // ignore any old packets
  }

  if (send_arp_request(iface, target_ip) != 0)
    return -1;

  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);

  while (1) {
    ret = pcap_next_ex(handle, &hdr, &packet);

    if (ret == 1) { // packet received
      if (hdr->caplen < sizeof(struct arp_packet))
        continue;

      const struct arp_packet *pkt = (const struct arp_packet *)packet;

      // check Ethernet type
      if (ntohs(pkt->eth.h_proto) != ETH_P_ARP)
        continue;

      // check ARP reply
      if (ntohs(pkt->arp.oper) != 2)
        continue;

      uint32_t sip;
      memcpy(&sip, pkt->arp.spa, 4);

      if (sip == target_ip.ipv4.s_addr) {
        memcpy(res->mac, pkt->arp.sha, 6);
        res->ok = 1;
        return 0;
      }
    } else if (ret < 0) {
      perror("pcap_next_ex");
      return -1;
    }

    // check timeout
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000;
    if (elapsed >= timeout_ms) {
      res->ok = 0;
      return 0;
    }
  }
}
