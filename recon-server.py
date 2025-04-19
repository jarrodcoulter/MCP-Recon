import asyncio
import sys
from mcp.server.fastmcp import FastMCP
import nmap

# Initialize the MCP server with a name
mcp = FastMCP("Recon Server")

@mcp.tool()
async def host_discovery(targets: str) -> dict:
    """Perform initial host discovery on a network. This tool uses nmap to run ICMP and Arp scan to dientify live hosts on target networks. If mulitple targets are provided and they are not in CIDR format, they should be space-separated."""
    # Initialize the Nmap port scanner
    scanner = nmap.PortScanner()
    # Run the scan in a thread to avoid blocking the event loop
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        lambda: scanner.scan(hosts=targets, arguments="-sn -PR -n --disable-arp-ping -oA nmap_host_discovery")
    )
    return result  # The scan result is a nested dictionary with scan details

@mcp.tool()
async def tcp_port_scan(targets: str) -> dict:
    """Perform a complete nmap TCP port scan on a network of all ports and return only open ports. This should only be run against live hosts.
    If mulitple targets are provided and they are not in CIDR format, they should be space-separated."""
    # Initialize the Nmap port scanner
    scanner = nmap.PortScanner()
    # Run the scan in a thread to avoid blocking the event loop
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        lambda: scanner.scan(hosts=targets, arguments="-T4 -p- --open -iL -oA nmap_tcp_port_scan")
    )
    return result  # The scan result is a nested dictionary with scan details

@mcp.tool()
async def udp_port_scan(targets: str) -> dict:
    """Perform a nmap UDP port scan on a network of the top 200 UDP ports and return only open ports. This should only be run against live hosts.
    If mulitple targets are provided and they are not in CIDR format, they should be space-separated."""
    # Initialize the Nmap port scanner
    scanner = nmap.PortScanner()
    # Run the scan in a thread to avoid blocking the event loop
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        lambda: scanner.scan(hosts=targets, arguments="-sU --top-ports 200 -T4 -oA nmap_udp_port_scan")
    )
    return result  # The scan result is a nested dictionary with scan details

@mcp.tool()
async def nmap_service_scan(targets: str, scanports: str) -> dict:
    """Perform a nmap service scan on a network in order to discover listening services. You must supply both the targets and TCP Ports to be scanned as arguments.
    This should only be run against live hosts. If mulitple targets are provided and they are not in CIDR format, they should be space-separated. 
    If multiple ports are provided, they should be comma-separated."""
    # Initialize the Nmap port scanner
    scanner = nmap.PortScanner()
    # Run the scan in a thread to avoid blocking the event loop
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        lambda: scanner.scan(hosts=targets, ports=scanports, arguments="-sV -sC -O -T4 -iL nmap_host_discovery.gnmap -oA nmap_service_scan")
    )
    return result  # The scan result is a nested dictionary with scan details

@mcp.tool()
async def nbt_scan(targets: str) -> dict:
    """Scan targets for NBT services (NETBIOS) on UDP port 137 using nmaps script nbstat.nse. Return hosts that have this service enabled. 
    If mulitple targets are provided and they are not in CIDR format, they should be space-separated."""
    # Initialize the Nmap port scanner
    scanner = nmap.PortScanner()
    # Run the scan in a thread to avoid blocking the event loop
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        lambda: scanner.scan(hosts=targets, arguments="-sU -p 137 --script nbstat.nse -oA nmap_nbstat")
    )
    return result  # The scan result is a nested dictionary with scan details

@mcp.tool()
async def ldap_scan(targets: str) -> dict:
    """Scan targets ldap and perform a basic search through the nmap ldap-search script. This targets port 389 and should be used against potential Domain Controllers
    or LDAP server. If mulitple targets are provided and they are not in CIDR format, they should be space-separated."""
    # Initialize the Nmap port scanner
    scanner = nmap.PortScanner()
    # Run the scan in a thread to avoid blocking the event loop
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        lambda: scanner.scan(hosts=targets, arguments="-p 389 --script ldap-search -n <DC_IP> -oA nmap_ldap_anon")
    )
    return result  # The scan result is a nested dictionary with scan details

@mcp.tool()
async def smb_share_enum(targets: str) -> dict:
    """Scan identified Windows hosts and enumerate smb shares using null credentials. If mulitple targets are provided and they are not in CIDR format, they should be space-separated."""
    # Initialize the Nmap port scanner
    scanner = nmap.PortScanner()
    # Run the scan in a thread to avoid blocking the event loop
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        lambda: scanner.scan(hosts=targets, arguments="-p 445 --script smb-enum-shares --script-args smbusername='',smbpassword='' -oA nmap_smb_shares_anon")
    )
    return result  # The scan result is a nested dictionary with scan details

@mcp.tool()
async def http_server_scan(targets: str, scanports: str) -> dict:
    """Scan identified web servers to discover server type and application against the supplied targets and scanports (ports you'd like scanned). 
    You must specify both targets and scanports to be scanned. If mulitple targets are provided and they are not in CIDR format, they should be space-separated."""
    # Initialize the Nmap port scanner
    scanner = nmap.PortScanner()
    # Run the scan in a thread to avoid blocking the event loop
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        lambda: scanner.scan(hosts=targets, ports=scanports, arguments="--script http-enum,http-title,http-headers,http-methods,http-wordpress-enum -oA nmap_http_enum")
    )
    return result  # The scan result is a nested dictionary with scan details

if __name__ == "__main__":
    # Run the MCP server over stdio (for use with `mcp dev` or other stdio clients)
    mcp.run(transport="stdio")