import requests
import json
import sys

def get_subdomains_from_crtsh(domain):
    """
    Queries crt.sh for subdomains of a given domain and returns a deduplicated list.

    Args:
        domain (str): The target domain (e.g., "example.com").

    Returns:
        list: A sorted list of unique subdomains found, or an empty list if none
              are found or an error occurs.
    """
    # Construct the URL for crt.sh API query
    # The '%' acts as a wildcard for subdomains.
    # output=json specifies the JSON output format.
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains = set() # Use a set for automatic deduplication

    print(f"[*] Querying crt.sh for subdomains of {domain}...")

    try:
        # Make the HTTP GET request
        response = requests.get(url, timeout=10) # Add a timeout for robustness
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)

        # Parse the JSON response
        data = response.json()

        # Extract subdomains from the JSON data
        for entry in data:
            # The 'common_name' field usually contains the domain or subdomain
            # The 'name_value' field can also contain multiple comma-separated values
            # that include subdomains.
            name_values = entry.get('name_value', '').split('\n') # Split by newline for multiple entries
            for name_value in name_values:
                name_value = name_value.strip()
                if name_value.endswith(f".{domain}") or name_value == domain:
                    subdomains.add(name_value)

    except requests.exceptions.Timeout:
        print(f"[!] Request to crt.sh timed out after 10 seconds.", file=sys.stderr)
    except requests.exceptions.RequestException as e:
        print(f"[!] Error querying crt.sh: {e}", file=sys.stderr)
    except json.JSONDecodeError:
        print(f"[!] Error decoding JSON response from crt.sh. Unexpected format.", file=sys.stderr)
    except Exception as e:
        print(f"[!] An unexpected error occurred during subdomain enumeration: {e}", file=sys.stderr)

    # Convert set to sorted list for consistent output
    return sorted(list(subdomains))

if __name__ == "__main__":
    # This block is for testing the module independently
    test_domain = "google.com" # You can change this to test other domains
    print(f"--- Testing get_subdomains_from_crtsh for {test_domain} ---")
    found_subdomains = get_subdomains_from_crtsh(test_domain)
    if found_subdomains:
        print(f"\nFound {len(found_subdomains)} unique subdomains for {test_domain}:")
        for subdomain in found_subdomains:
            print(f"  - {subdomain}")
    else:
        print(f"No subdomains found or an error occurred for {test_domain}.")
    print("--- Test Complete ---")
