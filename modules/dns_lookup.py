import dns.resolver
import dns.exception
import sys

def get_dns_records(domain):
    """
    Performs DNS lookups for A, AAAA, MX, TXT, and NS records for the given domain.

    Args:
        domain (str): The domain to perform DNS lookups on.

    Returns:
        dict: A dictionary containing lists of records for each type, or an empty
              list for a record type if none are found or an error occurs.
              Example: {
                  "A": ["192.0.2.1"],
                  "AAAA": ["2001:db8::1"],
                  "MX": ["mail.example.com (priority 10)"],
                  "TXT": ["v=spf1 include:_spf.example.com ~all"],
                  "NS": ["ns1.example.com", "ns2.example.com"]
              }
    """
    print(f"[*] Performing DNS lookup for {domain}...")
    dns_records = {
        "A": [],    # IPv4 addresses
        "AAAA": [], # IPv6 addresses
        "MX": [],   # Mail Exchange records
        "TXT": [],  # Text records
        "NS": []    # Name Server records
    }

    # Define the record types to query
    record_types = ["A", "AAAA", "MX", "TXT", "NS"]

    for record_type in record_types:
        try:
            # Query for the specific record type
            answers = dns.resolver.resolve(domain, record_type, lifetime=5) # Add a timeout (lifetime)

            for rdata in answers:
                if record_type == "MX":
                    # MX records have priority and exchange
                    dns_records[record_type].append(f"{rdata.exchange.to_text()} (priority {rdata.preference})")
                elif record_type == "TXT":
                    # TXT records can have multiple strings, join them
                    dns_records[record_type].append(rdata.strings[0].decode('utf-8'))
                else:
                    # For A, AAAA, NS, just get the address/name
                    dns_records[record_type].append(rdata.to_text())

        except dns.resolver.NXDOMAIN:
            # Domain does not exist
            # print(f"[!] {domain} does not exist (NXDOMAIN) for {record_type} records.", file=sys.stderr)
            pass # Suppress error for specific record type if domain doesn't exist
        except dns.resolver.NoAnswer:
            # No records of this type found for the domain
            # print(f"[!] No {record_type} records found for {domain}.", file=sys.stderr)
            pass # It's common for some record types not to exist, so don't treat as critical error
        except dns.resolver.Timeout:
            print(f"[!] DNS query for {record_type} records on {domain} timed out.", file=sys.stderr)
        except dns.exception.DNSException as e:
            # Catch other dnspython-specific exceptions
            print(f"[!] DNS error for {record_type} records on {domain}: {e}", file=sys.stderr)
        except Exception as e:
            # Catch any other unexpected errors
            print(f"[!] An unexpected error occurred during {record_type} DNS lookup for {domain}: {e}", file=sys.stderr)

    return dns_records

if __name__ == "__main__":
    # This block is for testing the module independently
    test_domain = "example.com" # Change this to test other domains
    print(f"--- Testing get_dns_records for {test_domain} ---")
    records = get_dns_records(test_domain)
    if records:
        print("\nDNS Records:")
        for record_type, values in records.items():
            if values:
                print(f"  {record_type} Records:")
                for value in values:
                    print(f"    - {value}")
            else:
                print(f"  {record_type} Records: No records found.")
    else:
        print(f"No DNS information found or an error occurred for {test_domain}.")
    print("--- Test Complete ---")
