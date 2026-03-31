#include "compat.h"

/* Compute standard RFC 1071 checksum over memory (returns checksum in host order) */
uint16_t checksum(void *b, int len) {
  uint16_t *buf = (uint16_t *)b;
  unsigned int sum = 0;

  while (len > 1) {
    sum += *buf++;
    len -= 2;
  }
  if (len == 1) {
    sum += *(uint8_t *)buf;
  }
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  return (uint16_t)(~sum);
}

