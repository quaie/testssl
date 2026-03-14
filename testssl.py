#!/usr/bin/env python3
import argparse
import sys
import json
from pathlib import Path
from typing import List, Dict, Any
import socket

# Correct sslyze 6.x imports [web:30][web:18]
from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.scanner.scanner import Scanner
from sslyze.server_scan_request import ServerScanRequest
from sslyze.errors import ServerHostnameCouldNotBeResolved, ConnectionToServerError

def resolve_ips(domain: str) -> str:
    try:
        ips = [str(ip) for ip in socket.getaddrinfo(domain, None, family=socket.AF_INET)]
        return ", ".join(set(ips))  # Unique
    except:
        return ""

def scan_domain(domain: str) -> Dict[str, str]:
    target = f"{domain}:443"
    ips = resolve_ips(domain)
    
    try:
        tester = ServerConnectivityTester()
        server_info = tester.perform(target, hostname=domain)  # SNI via hostname
    except (ServerHostnameCouldNotBeResolved, ConnectionToServerError):
        return {"domain": domain, "ip_addresses": ips, "tls_versions_supported": "", "list_of_ciphers": ""}
    
    scanner = Scanner()
    request = ServerScanRequest(server_info=server_info)
    scanner.queue_scan(request)
    
    for completed_scan in scanner.get_results():
        tls_versions = ", ".join(proto.name for proto in completed_scan.accepted_protocols)
        ciphers = ", ".join(cipher.name for cipher in completed_scan.cipher_suites.accepted_cipher_suites)[:200]  # Trunc
        return {
            "domain": domain,
            "ip_addresses": ips,
            "tls_versions_supported": tls_versions,
            "list_of_ciphers": ciphers
        }
    
    return {"domain": domain, "ip_addresses": ips, "tls_versions_supported": "", "list_of_ciphers": ""}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--domains", default="domains.txt")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    
    domains_file = Path(args.domains)
    if not domains_file.exists():
        print(f"Error: {args.domains} not found", file=sys.stderr)
        sys.exit(1)
    
    domains = [line.strip() for line in domains_file.read_text().splitlines() if line.strip()]
    results: List[Dict[str, str]] = []
    
    for domain in domains:
        sys.stderr.write(f"Scanning {domain}...\n")
        result = scan_domain(domain)
        results.append(result)
    
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(json.dumps(r))

if __name__ == "__main__":
    main()
