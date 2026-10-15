import os
import subprocess
from pathlib import Path

import pytest

BIN = Path(__file__).resolve().parents[1] / "ipk-L2L3-scan"


def run_bin(args, timeout=10):
    return subprocess.run(
        [str(BIN), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def require_root():
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    # On non-POSIX systems geteuid may not exist; treat as not-root.
    return False


# -------------------------
# Build / sanity
# -------------------------

def test_binary_exists():
    assert BIN.exists(), "Binary ipk-L2L3-scan not found. Run `make` first."
    assert os.access(BIN, os.X_OK), "Binary is not executable."


# -------------------------
# CLI behavior (stable tests)
# -------------------------

def test_help_prints_usage_and_exits_ok():
    cp = run_bin(["-h"])
    assert cp.returncode == 0
    assert "Usage:" in cp.stdout
    assert "./ipk-L2L3-scan -i INTERFACE" in cp.stdout


def test_unknown_argument_fails():
    cp = run_bin(["--definitely-not-a-real-flag"])
    assert cp.returncode != 0
    assert "Unknown argument" in cp.stderr


def test_missing_interface_value_lists_interfaces_mode():
    # args.c: "-i" with no value => list_interfaces=1
    cp = run_bin(["-i"])
    assert cp.returncode == 0
    assert "Active interfaces:" in cp.stdout


def test_missing_required_interface_fails():
    cp = run_bin(["-s", "127.0.0.1/32"])
    assert cp.returncode != 0
    assert "Interface must be specified" in cp.stderr


def test_invalid_timeout_fails():
    cp = run_bin(["-i", "lo", "-w", "abc"])
    assert cp.returncode != 0
    assert "Could not convert given timeout to integer" in cp.stderr


# -------------------------
# Scan tests (expect sudo/root)
# -------------------------

@pytest.mark.skipif(not require_root(), reason="Scan tests require root (run: sudo make test)")
def test_scan_ipv4_localhost_smoke():
    iface = os.environ.get("TEST_IFACE", "lo")
    # Keep it quick
    cp = run_bin(["-i", iface, "-s", "127.0.0.1/32", "-w", "300"], timeout=15)

    # If pcap cannot open on given iface, it will fail. In that case show useful output.
    assert cp.returncode == 0, f"stdout:\n{cp.stdout}\n\nstderr:\n{cp.stderr}"
    assert "Scanning ranges:" in cp.stdout
    # We don't strictly require arp/icmp OK (environment dependent), just that scan ran and printed something.
    assert "127.0.0.1" in cp.stdout


@pytest.mark.skipif(not require_root(), reason="Scan tests require root (run: sudo make test)")
def test_scan_ipv6_localhost_smoke_optional():
    """
    Optional IPv6 smoke test.
    Some environments might not have ::1 reachable in a way that your NDP/ICMPv6 path expects on 'lo',
    so this is marked as xfail if it fails.
    """
    iface = os.environ.get("TEST_IFACE", "lo")

    cp = run_bin(["-i", iface, "-s", "::1/128", "-w", "300"], timeout=15)

    if cp.returncode != 0:
        pytest.xfail(f"IPv6 scan failed (environment-dependent). stdout:\n{cp.stdout}\n\nstderr:\n{cp.stderr}")

    assert "Scanning ranges:" in cp.stdout
    assert "::1" in cp.stdout
