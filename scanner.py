"""Simple TCP port scanner that checks a range of ports on a target host."""
# Testing windows: py -m http.server 8000 --bind 127.0.0.1
# Testing linux: python3 -m http.server 8000 --bind 127.0.0.1

import argparse
from scanner_functions import parse_port_range, scan_port, validate_target


def main():
    """Parse command-line arguments and scan the specified port range."""
    parser = argparse.ArgumentParser(description="Port Scanner")
    # Command-line arguments for target, port range, and timeout
    parser.add_argument("--target", default="127.0.0.1", help="target IPv4 address")
    parser.add_argument("--ports",required=True, help="Port range to scan (e.g., 20-80, or 80 for a single port)")
    parser.add_argument("--timeout", type=float, default=4, help="Timeout in seconds for each port scan. Timeout under about 2 seconds turned refused connections on Windows into 'unknown' on my machine")
    args = parser.parse_args()

    # Validate the timeout value
    if args.timeout <= 0:
        parser.error("Timeout must be a positive number.")

    # Validate the target and port range
    try:
        target = validate_target(args.target)
        initial_port, end_port = parse_port_range(args.ports)
    except ValueError as e:
        parser.error(str(e))

    # Header
    print(f"Scanning {target}...\n")

    # Scan each port in the specified range
    for port in range(initial_port, end_port + 1):
        status = scan_port(target, port, args.timeout)
        print(f"Port {port} is {status}")

    # Footer
    print("\nScan complete.")


if __name__ == "__main__":
    main()