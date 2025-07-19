import re
from urllib.parse import urlparse

# --- Configuration for heuristic checks ---
# You can customize these thresholds and patterns
MAX_URL_LENGTH = 100  # Maximum recommended URL length
MAX_SUBDOMAINS = 3   # Maximum number of subdomains before it gets suspicious
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "secure", "update", "password", "bank",
    "paypal", "amazon", "apple", "microsoft", "google", "support", "billing"
]
COMMON_TYPOS = {
    "google.com": ["go0gle.com", "g0ogle.com", "gooogle.com"],
    "amazon.com": ["amaz0n.com", "amazonn.com", "amzon.com"],
    "paypal.com": ["paypa1.com", "paypall.com", "paypol.com"],
    "microsoft.com": ["micr0soft.com", "microsof.com", "mircosoft.com"],
    "apple.com": ["appple.com", "aple.com", "aapple.com"],
    # Add more common legitimate domains and their potential typos
}

def is_ip_address(hostname):
    """
    Checks if the hostname is an IP address.
    Phishers often use IP addresses directly to avoid domain registration.
    """
    # IPv4 pattern
    ipv4_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ipv4_pattern.match(hostname):
        # Validate each octet is within 0-255
        parts = list(map(int, hostname.split('.')))
        if all(0 <= part <= 255 for part in parts):
            return True

    # IPv6 pattern (basic check, can be more comprehensive)
    # This is a simplified check for common IPv6 formats
    ipv6_pattern = re.compile(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
    if ipv6_pattern.match(hostname):
        return True

    return False

def check_url_length(url):
    """
    Checks if the URL is unusually long, which can be a sign of obfuscation.
    """
    if len(url) > MAX_URL_LENGTH:
        return True, f"URL is unusually long ({len(url)} characters)."
    return False, ""

def check_subdomain_count(hostname):
    """
    Checks for an excessive number of subdomains.
    Phishers sometimes use many subdomains to hide the true domain.
    """
    # Split by dot and filter out empty strings (e.g., if hostname ends with a dot)
    parts = [part for part in hostname.split('.') if part]
    # A simple way to estimate actual subdomains is to count parts minus TLD and main domain
    # This is a simplification; a more robust check would involve a public suffix list.
    if len(parts) > MAX_SUBDOMAINS + 1: # +1 for the main domain
        return True, f"Excessive number of subdomains ({len(parts) - 1})."
    return False, ""

def check_https(scheme):
    """
    Checks if the URL uses HTTPS.
    Legitimate sites, especially those requiring credentials, should use HTTPS.
    """
    if scheme.lower() != "https":
        return True, "Does not use HTTPS (HTTP detected)."
    return False, ""

def check_suspicious_keywords(path, query):
    """
    Checks for suspicious keywords in the URL path or query parameters.
    """
    full_path = (path + "?" + query).lower() if query else path.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in full_path:
            return True, f"Contains suspicious keyword: '{keyword}'."
    return False, ""

def check_typosquatting(hostname):
    """
    Performs a basic check for typosquatting against a predefined list of common domains.
    This is a very simple check and not exhaustive.
    """
    for legitimate_domain, typos in COMMON_TYPOS.items():
        if hostname.lower() in typos:
            return True, f"Potential typosquatting detected (resembles '{legitimate_domain}')."
    return False, ""

def check_special_characters_in_hostname(hostname):
    """
    Checks for unusual or encoded characters in the hostname that might be used for obfuscation.
    """
    # This regex allows letters, numbers, hyphens, and dots. Anything else is suspicious.
    # It specifically looks for characters that are not typically allowed in a standard hostname.
    # Note: Punycode (IDN) uses 'xn--' prefix, which is legitimate but can be abused.
    if re.search(r"[^a-zA-Z0-9\-\.]", hostname):
        return True, "Contains unusual or special characters in the hostname."
    return False, ""

def scan_url(url):
    """
    Scans a given URL for potential phishing indicators using various heuristics.
    Returns a dictionary of findings.
    """
    findings = {
        "is_phishing_suspect": False,
        "reasons": [],
        "parsed_url": {}
    }

    try:
        parsed_url = urlparse(url)
        findings["parsed_url"] = {
            "scheme": parsed_url.scheme,
            "netloc": parsed_url.netloc,
            "hostname": parsed_url.hostname,
            "port": parsed_url.port,
            "path": parsed_url.path,
            "query": parsed_url.query,
            "fragment": parsed_url.fragment
        }

        # 1. Check for IP address in hostname
        if parsed_url.hostname and is_ip_address(parsed_url.hostname):
            findings["is_phishing_suspect"] = True
            findings["reasons"].append("Hostname is an IP address.")

        # 2. Check URL length
        is_long, reason_long = check_url_length(url)
        if is_long:
            findings["is_phishing_suspect"] = True
            findings["reasons"].append(reason_long)

        # 3. Check subdomain count
        if parsed_url.hostname:
            is_excessive_subdomains, reason_subdomains = check_subdomain_count(parsed_url.hostname)
            if is_excessive_subdomains:
                findings["is_phishing_suspect"] = True
                findings["reasons"].append(reason_subdomains)

        # 4. Check for HTTPS
        is_http, reason_http = check_https(parsed_url.scheme)
        if is_http:
            findings["is_phishing_suspect"] = True
            findings["reasons"].append(reason_http)

        # 5. Check for suspicious keywords in path/query
        is_suspicious_keyword, reason_keyword = check_suspicious_keywords(parsed_url.path, parsed_url.query)
        if is_suspicious_keyword:
            findings["is_phishing_suspect"] = True
            findings["reasons"].append(reason_keyword)

        # 6. Basic typosquatting check
        if parsed_url.hostname:
            is_typo, reason_typo = check_typosquatting(parsed_url.hostname)
            if is_typo:
                findings["is_phishing_suspect"] = True
                findings["reasons"].append(reason_typo)

        # 7. Check for special characters in hostname
        if parsed_url.hostname:
            is_special_char, reason_special_char = check_special_characters_in_hostname(parsed_url.hostname)
            if is_special_char:
                findings["is_phishing_suspect"] = True
                findings["reasons"].append(reason_special_char)

    except Exception as e:
        findings["is_phishing_suspect"] = True
        findings["reasons"].append(f"Error parsing URL: {e}")

    return findings

if __name__ == "__main__":
    print("--- Python Phishing Link Scanner ---")
    print("Enter 'exit' to quit.")

    while True:
        user_input_url = input("\nEnter URL to scan: ").strip()

        if user_input_url.lower() == 'exit':
            print("Exiting scanner. Goodbye!")
            break

        if not user_input_url:
            print("Please enter a URL.")
            continue

        # Prepend 'http://' if no scheme is provided, for proper parsing
        if not re.match(r"^[a-zA-Z]+://", user_input_url):
            user_input_url = "http://" + user_input_url

        scan_results = scan_url(user_input_url)

        print("\n--- Scan Results ---")
        print(f"URL: {user_input_url}")
        print(f"Suspected Phishing: {'YES' if scan_results['is_phishing_suspect'] else 'NO'}")

        if scan_results["reasons"]:
            print("Reasons:")
            for reason in scan_results["reasons"]:
                print(f"  - {reason}")
        else:
            print("No suspicious indicators found based on current heuristics.")

        print("\n--- Parsed URL Details ---")
        for key, value in scan_results["parsed_url"].items():
            print(f"  {key.capitalize()}: {value if value else 'N/A'}")

        print("-" * 30)
