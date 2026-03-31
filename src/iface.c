#include "iface.h"
#include <stdio.h>
#include <string.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

int list_interfaces(void) {
  struct ifaddrs *ifaddr, *ifa;

  if (getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
    return -1;
  }

  printf("Active interfaces:\n");

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr)
      continue;

    if (ifa->ifa_addr->sa_family == AF_PACKET) {
      printf("  %s\n", ifa->ifa_name);
    }
  }

  freeifaddrs(ifaddr);
  return 0;
}

int get_interface_info(const char *ifname, iface_t *iface) {
  struct ifaddrs *ifaddr, *ifa;

  if (getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
    return -1;
  }

  memset(iface, 0, sizeof(iface_t));
  strncpy(iface->name, ifname, IF_NAMESIZE-1);
  iface->name[IF_NAMESIZE - 1] = '\0'; // ensure null-termination

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr || strcmp(ifa->ifa_name, ifname) != 0)
      continue;

    // MAC address
    if (ifa->ifa_addr->sa_family == AF_PACKET) {
      struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
      memcpy(iface->mac, s->sll_addr, 6);
    }

    // IPv4 address
    if (ifa->ifa_addr->sa_family == AF_INET) {
      struct sockaddr_in *s = (struct sockaddr_in*)ifa->ifa_addr;
      iface->ipv4 = s->sin_addr;
      iface->has_ipv4 = 1;
    }

    // IPv6 address
    if (ifa->ifa_addr->sa_family == AF_INET6) {
      struct sockaddr_in6 *s = (struct sockaddr_in6*)ifa->ifa_addr;
      iface->ipv6 = s->sin6_addr;
      iface->has_ipv6 = 1;
    }
  }

  freeifaddrs(ifaddr);
  return 0;
}
