import argparse
import sys
import os

# Import the new subdomain enumeration module
try:
    from modules.subdomain_enum import get_subdomains_from_crtsh
except ImportError:
    print("[!] Error: Could not import 'subdomain_enum' module. "
          "Make sure 'modules/subdomain_enum.py' exists.", file=sys.stderr)
    sys.exit(1)

# Import the new WHOIS lookup module
try:
    from modules.whois_lookup import get_whois_info
except ImportError:
    print("[!] Error: Could not import 'whois_lookup' module. "
          "Make sure 'modules/whois_lookup.py' exists.", file=sys.stderr)
    sys.exit(1)

# Import the new DNS lookup module
try:
    from modules.dns_lookup import get_dns_records
except ImportError:
    print("[!] Error: Could not import 'dns_lookup' module. "
          "Make sure 'modules/dns_lookup.py' exists.", file=sys.stderr)
    sys.exit(1)


def parse_port_range(port_range_str):
    """
    Parses a port range string (e.g., "1-1000") into a tuple of (start_port, end_port).
    Handles single port numbers as well (e.g., "80").
    """
    try:
        if '-' in port_range_str:
            start_str, end_str = port_range_str.split('-')
            start_port = int(start_str)
            end_port = int(end_str)
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                raise ValueError("Port numbers must be between 1 and 65535.")
            if start_port > end_port:
                raise ValueError("Start port cannot be greater than end port.")
            return (start_port, end_port)
        else:
            single_port = int(port_range_str)
            if not (1 <= single_port <= 65535):
                raise ValueError("Port number must be between 1 and 65535.")
            return (single_port, single_port) # Treat single port as a range
    except ValueError as e:
        # Re-raise with a more specific message for argparse
        raise argparse.ArgumentTypeError(f"Invalid port range format or value: {port_range_str}. {e}")

def perform_reconnaissance(domain, ports, output_file, enable_subdomains, enable_whois, enable_dns):
    """
    Performs reconnaissance tasks including simulated port scan, subdomain enumeration,
    WHOIS lookup, and DNS lookup, based on enabled flags.
    """
    print(f"\n--- Starting Reconnaissance for {domain} ---")
    print(f"Target Domain: {domain}")

    output_content = []
    output_content.append(f"Reconnaissance Report for: {domain}\n")
    output_content.append(f"Timestamp: {os.path.getmtime(__file__)}\n") # Using file modification time as a placeholder timestamp

    # --- Port Scanning Simulation ---
    output_content.append("\n--- Port Scan Simulation ---\n")
    if ports:
        if ports[0] == ports[1]:
            port_info = f"Scanning Port: {ports[0]}"
        else:
            port_info = f"Scanning Ports: {ports[0]} - {ports[1]}"
        print(port_info)
        output_content.append(f"{port_info}\n")
        # Simulate some findings for the port scan
        output_content.append("  - Found open port 80 (HTTP)\n")
        output_content.append("  - Found open port 443 (HTTPS)\n")
        print("  [+] Found open port 80 (HTTP)")
        print("  [+] Found open port 443 (HTTPS)")
    else:
        print("No specific ports provided for scanning (using default or common ports in simulation).")
        output_content.append("No specific ports provided for scanning (default/common ports).\n")

    # --- Subdomain Enumeration ---
    if enable_subdomains:
        print("\n--- Subdomain Enumeration ---")
        output_content.append("\n--- Subdomain Enumeration ---\n")
        subdomains = get_subdomains_from_crtsh(domain)
        if subdomains:
            output_content.append(f"Found {len(subdomains)} unique subdomains:\n")
            print(f"  [+] Found {len(subdomains)} unique subdomains:")
            for subdomain in subdomains:
                output_content.append(f"  - {subdomain}\n")
                print(f"    - {subdomain}")
        else:
            output_content.append("No subdomains found via crt.sh or an error occurred.\n")
            print("  [!] No subdomains found via crt.sh or an error occurred.")
    else:
        print("\n--- Subdomain enumeration skipped. ---")
        output_content.append("\nSubdomain enumeration skipped.\n")

    # --- WHOIS Lookup ---
    if enable_whois:
        print("\n--- WHOIS Lookup ---")
        output_content.append("\n--- WHOIS Lookup ---\n")
        whois_info = get_whois_info(domain)
        if whois_info:
            print("  [+] WHOIS Information Found:")
            output_content.append("WHOIS Information:\n")
            for key, value in whois_info.items():
                if isinstance(value, list):
                    line = f"  {key.replace('_', ' ').title()}:"
                    print(line)
                    output_content.append(f"{line}\n")
                    for item in value:
                        item_line = f"    - {item}"
                        print(item_line)
                        output_content.append(f"{item_line}\n")
                else:
                    line = f"  {key.replace('_', ' ').title()}: {value}"
                    print(line)
                    output_content.append(f"{line}\n")
        else:
            print("  [!] No WHOIS information found or an error occurred.")
            output_content.append("No WHOIS information found or an error occurred.\n")
    else:
        print("\n--- WHOIS lookup skipped. ---")
        output_content.append("\nWHOIS lookup skipped.\n")

    # --- DNS Lookup ---
    if enable_dns:
        print("\n--- DNS Lookup ---")
        output_content.append("\n--- DNS Lookup ---\n")
        dns_info = get_dns_records(domain)
        if dns_info:
            print("  [+] DNS Records Found:")
            output_content.append("DNS Records:\n")
            for record_type, records in dns_info.items():
                if records:
                    line = f"  {record_type} Records:"
                    print(line)
                    output_content.append(f"{line}\n")
                    for record_value in records:
                        record_line = f"    - {record_value}"
                        print(record_line)
                        output_content.append(f"{record_line}\n")
                else:
                    line = f"  {record_type} Records: No records found."
                    print(line)
                    output_content.append(f"{line}\n")
        else:
            print("  [!] No DNS information found or an error occurred.")
            output_content.append("No DNS information found or an error occurred.\n")
    else:
        print("\n--- DNS lookup skipped. ---")
        output_content.append("\nDNS lookup skipped.\n")


    # --- General Simulated Findings (can be combined with port scan findings) ---
    output_content.append("\n--- General Simulated Findings ---\n")
    simulated_general_findings = [
        "Identified web server: Nginx/1.18.0",
        "Discovered potential CMS: WordPress"
    ]
    for finding in simulated_general_findings:
        output_content.append(f"- {finding}\n")
        print(f"  [+] {finding}")


    # --- Output Results ---
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.writelines(output_content)
            print(f"\nReconnaissance results saved to: {output_file}")
        except IOError as e:
            print(f"Error: Could not write to output file '{output_file}': {e}", file=sys.stderr)
    else:
        print("\n--- End of Reconnaissance (results printed to console) ---")

def main():
    """
    Main function to set up argument parsing and initiate the reconnaissance.
    """
    # 1. Create an ArgumentParser object
    parser = argparse.ArgumentParser(
        description='A basic reconnaissance tool to gather information about a domain.',
        formatter_class=argparse.RawTextHelpFormatter, # Allows for multi-line descriptions
        epilog="""
Examples:
  python recon.py --domain example.com
  python recon.py --domain example.com --ports 80-443 --output report.txt
  python recon.py --domain secure.com --subdomains --whois --dns
  python recon.py --domain test.com --ports 22 --subdomains --whois --dns --output full_report.txt
"""
    )

    # 2. Add arguments

    # Required argument: --domain
    parser.add_argument(
        '--domain',
        type=str,
        required=True,
        help='The target domain for reconnaissance (e.g., example.com).'
    )

    # Optional argument: --ports with custom type parsing
    parser.add_argument(
        '--ports',
        type=parse_port_range, # Use our custom function to parse the range
        help='''Specify a port or a range of ports to scan (e.g., "80", "1-1000").
Ports must be between 1 and 65535.
'''
    )

    # Optional argument: --output
    parser.add_argument(
        '--output',
        type=str,
        help='Path to a file where reconnaissance results will be saved.'
    )

    # New optional flag: --subdomains
    parser.add_argument(
        '--subdomains',
        action='store_true', # If present, stores True; otherwise False
        help='Enable subdomain enumeration using crt.sh.'
    )

    # New optional flag: --whois
    parser.add_argument(
        '--whois',
        action='store_true', # If present, stores True; otherwise False
        help='Perform WHOIS lookup for domain registration details.'
    )

    # New optional flag: --dns
    parser.add_argument(
        '--dns',
        action='store_true', # If present, stores True; otherwise False
        help='Perform DNS record lookup (A, AAAA, MX, TXT, NS).'
    )

    # 3. Parse the arguments
    args = parser.parse_args()

    # 4. Use the parsed arguments
    perform_reconnaissance(args.domain, args.ports, args.output, args.subdomains, args.whois, args.dns)

if __name__ == "__main__":
    main()
