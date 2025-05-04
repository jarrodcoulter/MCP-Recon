# Multi-stage build: Stage 1 builds BruteSpray (Go), Stage 2 sets up Python server
FROM golang:1.22 AS build
WORKDIR /src
# Fetch BruteSpray source and build the binary
RUN git clone https://github.com/x90skysn3k/brutespray.git . \
 && go build -o /brutespray main.go

FROM python:3.12-slim AS final
WORKDIR /app
# Install Nmap in the slim image
RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir python-nmap modelcontextprotocol mcp
# Copy the BruteSpray binary from the builder stage
COPY --from=build /brutespray /usr/local/bin/brutespray
RUN chmod +x /usr/local/bin/brutespray
# Copy wordlists and server code into the image
COPY users.txt /app/users.txt
COPY pass.txt /app/pass.txt
COPY recon-server.py /app/recon-server.py
# Default command: run the MCP server (communicates over stdio)
CMD ["python", "recon-server.py"]
