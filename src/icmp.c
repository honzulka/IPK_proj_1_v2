#define _POSIX_C_SOURCE 199309L
#include "icmp.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <time.h>
#include <fcntl.h>
#include "compat.h"

// Send single ICMP echo request
static int send_icmp_request(ip_addr_t target_ip, uint16_t id, uint16_t seq) {
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sock < 0) { perror("socket"); return -1; }

  struct icmphdr icmp_hdr;
  memset(&icmp_hdr, 0, sizeof(icmp_hdr));

  icmp_hdr.type = ICMP_ECHO;
  icmp_hdr.code = 0;
  icmp_hdr.un.echo.id = htons(id);
  icmp_hdr.un.echo.sequence = htons(seq);
  icmp_hdr.checksum = 0;
  icmp_hdr.checksum = checksum(&icmp_hdr, sizeof(icmp_hdr));

  struct sockaddr_in dest;
  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_addr = target_ip.ipv4;

  if (sendto(sock, &icmp_hdr, sizeof(icmp_hdr), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
    perror("sendto");
    close(sock);
    return -1;
  }

  close(sock);
  return 0;
}

// Scan single host via ICMP, per-host timeout
int scan_single_icmp(ip_addr_t target_ip, int timeout_ms, icmp_result_t *res) {
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sock < 0) {
    perror("socket");
    return -1;
  }

  // set socket to be non-blocking
  int flags = fcntl(sock, F_GETFL, 0);
  if (flags == -1) { perror("fcntl get"); return -1; }

  if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
      perror("fcntl set");
      return -1;
  }

  int elapsed = 0;

  uint16_t id = (uint16_t)getpid();
  uint16_t seq = 0;

  if (send_icmp_request(target_ip, id, seq) != 0) {
    close(sock);
    return -1;
  }

  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);

  uint8_t buffer[1024];

  while (1) {
    struct sockaddr_in src;
    socklen_t len = sizeof(src);

    recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&src, &len);

    // check timeout
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000;
    if (elapsed >= timeout_ms) {
      res->ok = 0;
      close(sock);
      return 0;
    }

    const struct iphdr *ip = (const struct iphdr*)buffer;

    if (ip->protocol != IPPROTO_ICMP)
      continue;

    const struct icmphdr *icmp = (const struct icmphdr*)(buffer + ip->ihl * 4);

    if (icmp->type != ICMP_ECHOREPLY)
      continue;

    if (ntohs(icmp->un.echo.id) != id ||
        ntohs(icmp->un.echo.sequence) != seq)
      continue;

    if (ip->saddr != target_ip.ipv4.s_addr)
      continue;

    res->ok = 1;
    close(sock);
    return 0;
  }
}
