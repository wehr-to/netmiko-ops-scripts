import ipaddress

def summarize_network(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return {
            "network": str(net.network_address),
            "broadcast": str(net.broadcast_address),
            "num_hosts": net.num_addresses - 2,
            "wildcard_mask": str(ipaddress.IPv4Address(~int(net.netmask))),
            "host_range": f"{net.network_address + 1} - {net.broadcast_address - 1}"
        }
    except ValueError as e:
        return {"error": str(e)}

# This script automates subnet calculations I originally learned by hand for the CCNA. It reinforces what I know while showing how I’d apply that knowledge in production.
# Capable of handling IPv4 and IPv6 logic
