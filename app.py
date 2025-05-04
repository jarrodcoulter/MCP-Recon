import os, asyncio, shlex
from agents import Agent, Runner
from agents.mcp import MCPServerStdio

# sanity check API key
if not os.getenv("OPENAI_API_KEY"):
    raise EnvironmentError("Set the OPENAI_API_KEY environment variable.")

# get target from user
target = input("Enter target IP or CIDR range to scan: ").strip()
if not target:
    raise ValueError("Target cannot be empty.")

# build MCP stdio server (Docker)
toolkit_cmd = "run -v ./app:/app/output --rm -i recon-server"
recon_server = MCPServerStdio(
    name="ReconServer",
    params={"command": "docker", "args": shlex.split(toolkit_cmd)},
    client_session_timeout_seconds=600,
    cache_tools_list=True,
)

# define agent
agent = Agent(
    name="ReconAgent",
    instructions=(
        "You are an expert penetration tester. Use the tools provided by ReconServer to scan the target network and identify vulnerabilities.. "
        "First, use the `nmap_service_scan` tool to map out live hosts and open ports on the target. "
        "After scanning, if you find any services that require authentication (e.g., SSH, FTP, RDP, etc.), use the `brute_force` tool to attempt common credentials on those services. "
        "Analyze all tool outputs carefully. Finally, provide a comprehensive penetration test report in Markdown format, with the following sections (use Markdown headings for each):\n"
        "1. **Network topology & live hosts** – Describe the network range and which hosts responded to the scan.\n"
        "2. **Port/service inventory** – List each discovered open port and the corresponding service/application (including version info if available).\n"
        "3. **Misconfigurations & findings** – Highlight any unusual configurations or noteworthy findings (e.g., default credentials, outdated software).\n"
        "4. **Password-spray results** – Provide results of the credential spray (mention any valid credentials found or if none were successful).\n"
        "5. **Potential vulnerabilities & CVE references** – Based on the services and findings, identify possible vulnerabilities and relevant CVE IDs.\n"
        "6. **Where to go from here** – Suggest next steps to take as part of the pentest and further actions to exploit the network.\n"
        "7. **Recommendations & next steps** – Suggest remediation steps and further actions to secure the network.\n"
        "Be very detailed in your analysis and ensure the report is well-structured and formatted in Markdown."
    ),
    mcp_servers=[recon_server],
)
async def main():
    async with recon_server:
        report_md = await Runner.run(agent, input=f"Please perform a penetration test on the target network {target} and provide a detailed report.")
    print("\n=== FINAL REPORT ===\n")
    print(report_md)
    print("\n=== END OF REPORT ===\n")

# entry‑point
if __name__ == "__main__":
    asyncio.run(main())

