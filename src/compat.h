/**
 * @file compat.h
 * @brief Small compatibility typedefs and common utilities.
 */

#ifndef COMPAT_H
#define COMPAT_H

#include <stdint.h>

#ifndef u_char
typedef uint8_t u_char;
#endif

#ifndef u_short
typedef uint16_t u_short;
#endif

#ifndef u_int
typedef uint32_t u_int;
#endif

/**
 * @brief Compute RFC 1071 checksum over a memory buffer.
 *
 * @param b Pointer to buffer.
 * @param len Buffer length in bytes.
 * @return Checksum in host byte order.
 */
uint16_t checksum(void *b, int len);

#endif
