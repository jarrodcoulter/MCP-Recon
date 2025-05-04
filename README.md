# MCP-Recon

An AI-augmented workflow leveraging the Multi-Context Platform (MCP) to perform network reconnaissance tasks. This server provides tools for scanning networks and attempting brute-force attacks on discovered services.

## Features

This MCP server exposes the following tools:

1.  **`nmap_service_scan(targets: str)`**
    *   **Purpose:** Performs an Nmap service version scan (`-sV -T4`) on the specified targets to discover open ports and listening services.
    *   **Parameters:**
        *   `targets`: A string containing the target IP addresses, hostnames, or network ranges. Multiple targets should be space-separated if not using CIDR notation.
    *   **Returns:** A dictionary containing the Nmap scan results.

2.  **`brute_force(target: str)`**
    *   **Purpose:** Attempts to find valid credentials for a single service using default user/password lists via the `brutespray` tool.
    *   **Parameters:**
        *   `target`: A string specifying the target service in the format `service://ip:port` (e.g., `ssh://192.168.1.10:22`).
    *   **Dependencies:** Requires `brutespray` to be installed and accessible in the environment. It also expects user and password lists at `/app/users.txt` and `/app/pass.txt`, respectively.
    *   **Returns:** A string containing the output from `brutespray`, indicating found credentials or that none were found.

## Running the Client

Install the requirements:

```bash
pip install openai-agents
```

## Bulid the MCP Server
```bash
docker build -t recon-server .
```

## Run the app
```bash
python3.12 app.py
```