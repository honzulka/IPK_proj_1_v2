# Changelog

All notable changes to this project are documented in this file.

## 2026-04-04
### Changed
- Finished README.md
- Changed Makefile to support `make pack` command.

### Added 
- Images: Images for readme.

---

## [2026-03-31]
### Fixed
- **NDP / ICMPv6 capture reliability:** corrected packet capture filter setup (BPF) to reliably capture expected packets.
### Added
- **Tests:** added basic Python tests for CLI and scanning scenarios.
- **Documentation:** added Doxygen comments and a basic README.

### Changed
- **Refactor / cleanup:** unified checksum implementation in `compat.c`, improved pcap handle usage, unified types, and added `const` where appropriate.

---

## [2026-03-30]
### Added
- **ICMPv6 echo scan:** implemented ICMPv6 echo request scanning using a destination MAC address derived via NDP.
- **IPv6 NDP support:** implemented Neighbor Discovery Protocol support (send Neighbor Solicitation + receive Neighbor Advertisement).

### Changed
- **IP address abstraction:** replaced raw `uint32_t` IPv4 usage with `ip_addr_t` and introduced IPv6 groundwork across the codebase.

---

## [2026-03-22]
### Added
- **ICMPv4 echo scan:** implemented ICMPv4 echo request scanning.

---

## [2026-03-21]
### Added
- **ARP + subnet integration:** integrated subnet iteration with ARP request logic and a pcap-based ARP listener to collect replies.

---

## [2026-03-20]
### Added
- **ARP request sending:** implemented ARP request sending via raw sockets.

---

## [2026-03-19]
### Added
- **IPv4 subnet parsing and iteration:** implemented parsing of IPv4 subnets and host iteration across the range.
- **Interface discovery:** added `iface.c/h` to list interfaces and retrieve interface MAC/IP information.

---

## [2026-03-18]
### Added
- **CLI foundation:** initial command-line parsing (`args.h/c`), `main.c` entry point, and a simple Makefile.
- **Initial commit:** repository baseline.
