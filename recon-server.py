import asyncio
from mcp.server.fastmcp import FastMCP
import nmap
import subprocess


# Initialize the MCP server with a name
mcp = FastMCP("Recon Server")

@mcp.tool()
async def nmap_service_scan(targets: str) -> dict:
    """Perform a nmap service scan on a network in order to discover listening services. You must supply both the targets and TCP Ports to be scanned as arguments.
    This should only be run against live hosts. If mulitple targets are provided and they are not in CIDR format, they should be space-separated. 
    If multiple ports are provided, they should be comma-separated."""
    scanner = nmap.PortScanner()
    # Run the scan in a thread to avoid blocking the event loop
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        lambda: scanner.scan(hosts=targets, arguments="-T4 -sV")
    )
    return result

@mcp.tool()
def brute_force(target: str) -> str:
    """Attempt common default credentials on a service. Example brutespray -H ssh://127.0.0.1:22 -u userlist -p passlist.
    ensure each service is in the format service://ip:port. This can only be run against a single service at a time."""
    # Ensure previous scan output exists
    try:
        # Run BruteSpray with the users and passwords list on the Nmap XML output
        result = subprocess.run(
            ["brutespray", "-H", target, "-u", "/app/users.txt", "-p", "/app/pass.txt", "-q"],
            check=True, capture_output=True, text=True
        )
    except subprocess.CalledProcessError as e:
        return f"BruteSpray failed: {e}"
    # Return BruteSpray output (any found credentials or summary will be in stdout)
    output = result.stdout.strip()
    if not output:
        output = "BruteSpray completed – no valid credentials found."
    return output

if __name__ == "__main__":
    # Run the MCP server over stdio (for use with `mcp dev` or other stdio clients)
    mcp.run(transport="stdio")