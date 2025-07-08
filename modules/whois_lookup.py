import whois
import sys
from datetime import datetime

def get_whois_info(domain):
    """
    Performs a WHOIS lookup for the given domain and extracts key information.

    Args:
        domain (str): The domain to perform the WHOIS lookup on.

    Returns:
        dict: A dictionary containing extracted WHOIS information (creation_date,
              expiration_date, registrar, name_servers), or None if an error occurs.
    """
    print(f"[*] Performing WHOIS lookup for {domain}...")
    whois_info = {
        "creation_date": None,
        "expiration_date": None,
        "registrar": None,
        "name_servers": []
    }

    try:
        # Perform the WHOIS query
        # Adding a timeout for robustness
        # Note: python-whois might not have a direct timeout parameter for the lookup itself,
        # but the underlying socket operations will eventually time out.
        # For more robust timeouts, consider wrapping in a separate thread with a timeout.
        domain_info = whois.whois(domain)

        if domain_info is None:
            print(f"[!] WHOIS lookup failed or no information found for {domain}.", file=sys.stderr)
            return None

        # Extract creation date
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            # If multiple dates, take the first one or join them
            whois_info["creation_date"] = [d.strftime('%Y-%m-%d %H:%M:%S') if isinstance(d, datetime) else str(d) for d in creation_date]
        elif isinstance(creation_date, datetime):
            whois_info["creation_date"] = creation_date.strftime('%Y-%m-%d %H:%M:%S')
        else:
            whois_info["creation_date"] = str(creation_date)

        # Extract expiry date
        expiration_date = domain_info.expiration_date
        if isinstance(expiration_date, list):
            # If multiple dates, take the first one or join them
            whois_info["expiration_date"] = [d.strftime('%Y-%m-%d %H:%M:%S') if isinstance(d, datetime) else str(d) for d in expiration_date]
        elif isinstance(expiration_date, datetime):
            whois_info["expiration_date"] = expiration_date.strftime('%Y-%m-%d %H:%M:%S')
        else:
            whois_info["expiration_date"] = str(expiration_date)


        # Extract registrar
        registrar = domain_info.registrar
        if isinstance(registrar, list):
            whois_info["registrar"] = ", ".join(registrar)
        else:
            whois_info["registrar"] = str(registrar)

        # Extract name servers
        name_servers = domain_info.name_servers
        if isinstance(name_servers, list):
            # Ensure all nameservers are uppercase as is common convention
            whois_info["name_servers"] = [ns.upper() for ns in name_servers if ns]
        elif name_servers: # Check if it's not None or empty string
            whois_info["name_servers"] = [str(name_servers).upper()]

        return whois_info

    except whois.parser.PywhoisError as e:
        print(f"[!] WHOIS parsing error for {domain}: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred during WHOIS lookup for {domain}: {e}", file=sys.stderr)
        return None

if __name__ == "__main__":
    # This block is for testing the module independently
    test_domain = "google.com" # Change this to test other domains
    print(f"--- Testing get_whois_info for {test_domain} ---")
    info = get_whois_info(test_domain)
    if info:
        print("\nWHOIS Information:")
        for key, value in info.items():
            if isinstance(value, list):
                print(f"  {key.replace('_', ' ').title()}:")
                for item in value:
                    print(f"    - {item}")
            else:
                print(f"  {key.replace('_', ' ').title()}: {value}")
    else:
        print(f"No WHOIS information found or an error occurred for {test_domain}.")
    print("--- Test Complete ---")
