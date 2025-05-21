# Cisco ACL Formatter (IPv4 only)
import ipaddress

def generate_acl_line(cidr):
    """
    Generate a Cisco standard access-list line from a CIDR block.
    Example: "192.168.1.0/24" ➝ "access-list 10 permit 192.168.1.0 0.0.0.255"
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if not isinstance(net, ipaddress.IPv4Network):
            return {"error": "Only IPv4 networks are supported."}
        
        wildcard = ipaddress.IPv4Address(~int(net.netmask))
        return f"access-list 10 permit {net.network_address} {wildcard}"
    except ValueError as e:
        return {"error": str(e)}


# Subnet a larger block (IPv4)
def subnet_block(cidr, new_prefix):
    """
    Subdivide a CIDR block into smaller subnets.
    Example: ("192.168.0.0/24", 26) ➝ Four /26 blocks
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        subnets = list(net.subnets(new_prefix=new_prefix))
        return [str(subnet) for subnet in subnets]
    except ValueError as e:
        return {"error": str(e)}
      
# Subnet a block for (IPv6)
def subnet_ipv6_block(cidr, new_prefix=64):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if not isinstance(net, ipaddress.IPv6Network):
            return {"error": "Only IPv6 networks are supported."}

        subnets = list(net.subnets(new_prefix=new_prefix))
        return [str(subnet) for subnet in subnets]
    except ValueError as e:
        return {"error": str(e)}

# All scripts are cisco specific 
