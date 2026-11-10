
import socket
import errno
import ipaddress

# Error codes that mean the connection was refused (10061 is the Windows equivalent)
REFUSED_CODES = {errno.ECONNREFUSED, 10061}

def validate_target(raw_target):
    """Return raw_target as an ipaddress string if it is a valid IPv4 address, else raise ValueError."""
    raw_target = raw_target.strip()  # Remove whitespace from the input
    # Validate the target as an IPv4 address
    try:
        target = ipaddress.IPv4Address(raw_target)
    except ValueError:
        raise ValueError(f"'{raw_target}' is not a valid IPv4 address.") from None

    return str(target)

def validate_port(raw_port):
    """Return raw_port as an int if it is a valid port number, else raise ValueError."""
    # Make sure the value can be converted to a whole number
    try:
        port_num = int(raw_port)
    except ValueError:
        raise ValueError(f"'{raw_port}' is not a whole number.") from None

    # Valid TCP ports run from 1 to 65535
    if not (1 <= port_num <= 65535):
        raise ValueError(f"Port {port_num} is out of range (1-65535).")

    return port_num

def parse_port_range(text):
    """Parse a port range string like '20-80' and return the start and end ports as integers."""
    pieces = text.split("-")
    # Split the input text by the hyphen to separate start and end ports
    if len(pieces) == 1:
        start = end = validate_port(pieces[0])
    elif len(pieces) == 2:
        start = validate_port(pieces[0])
        end = validate_port(pieces[1])
    else:
        raise ValueError(f"Invalid port range: {text}")
    if start > end: raise ValueError(f"Start value larger than end value: {text}")

    return start, end

def scan_port(target, port, timeout = 4):
    """Attempt a TCP connection to the target port and return its status."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:   # Creates an IPv4 TCP socket
        client.settimeout(timeout)  # Timeout to prevent waiting
        # Attempt TCP connection (returns 0 on success instead of raising an error)
        result = client.connect_ex((target, port))

        # Check connection status and return result
        if result == 0:
            return "open"
        elif result in REFUSED_CODES:
            return "closed" 
        else:
            return "unknown"