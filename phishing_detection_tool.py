import re
import requests
import dns.resolver
import time
import argparse
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

# VirusTotal API Key (replace with your own key)
API_KEY = 'ec997346cf668c7b6b40c49efb1cf8e0509a52b66709c13f99271f25cc858c36'

# Rate limits (VirusTotal free tier allows 4 requests per minute)
RATE_LIMIT = 4
SLEEP_INTERVAL = 60 / RATE_LIMIT  # Time to wait between requests (15 seconds)

# Function to check if a URL has suspicious patterns
def is_suspicious_url(url):
    pattern = r"https?://(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/|$)"
    if not re.match(pattern, url):
        return True
    if any(keyword in url for keyword in ["phish", "fraud", "malicious", "fake"]):
        return True
    return False

# Function to check SSL certificate validity using requests
def check_ssl_certificate(url):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            print(Fore.GREEN + "SSL certificate is valid.")
            return True
    except requests.exceptions.SSLError as e:
        print(Fore.RED + f"SSL Error: {e}")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error connecting to {url}: {e}")
    return False

# Function to check URL against VirusTotal API
def check_url_virustotal(url):
    api_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {'apikey': API_KEY, 'resource': url}
    try:
        response = requests.get(api_url, params=params)
        response.raise_for_status()  # Raises an HTTPError for bad responses (4xx, 5xx)
        result = response.json()
        if result.get('response_code') == 1:
            positives = result.get('positives', 0)
            return True if positives > 0 else False, positives
    except requests.exceptions.RequestException as e:
        print(f"Error querying VirusTotal API: {e}")
        return False, 0
    return False, 0

# Function to check SPF records
def check_spf(domain):
    try:
        result = dns.resolver.resolve(domain, 'TXT')
        for txt_record in result:
            if 'v=spf1' in txt_record.to_text():
                return True
    except dns.resolver.NoAnswer:
        return False
    return False

# Function to check if the email is spoofed by comparing From and Reply-To headers
def check_email_spoofing(email_header):
    if email_header.get('From') != email_header.get('Reply-To'):
        return True
    return False

# Function to analyze email headers
def analyze_email_header(email_header):
    print("Analyzing Email Header...")

    # Extract domain from 'From' field
    from_domain = re.search(r'@([\w.-]+)', email_header.get('From')).group(1)

    # SPF Check
    spf_valid = check_spf(from_domain)
    if spf_valid:
        print(Fore.GREEN + "SPF check passed.")
    else:
        print(Fore.RED + "SPF check failed.")
    
    # Email spoofing detection
    if check_email_spoofing(email_header):
        print(Fore.RED + "Warning: Email header has inconsistencies (potential spoofing).")
    else:
        print(Fore.GREEN + "Email header is consistent.")

    return spf_valid, check_email_spoofing(email_header)

# Sample email header input
def get_email_header():
    print("Enter email header details:")
    email_header = {}
    email_header['From'] = input("From: ")
    email_header['Reply-To'] = input("Reply-To: ")
    return email_header

# Function to generate phishing detection report
def generate_report(url, is_blacklisted, cert_valid, email_check):
    report = f"Phishing Detection Report for {url}:\n"
    report += f"- Blacklisted: {is_blacklisted}\n" if is_blacklisted else "- URL not blacklisted.\n"
    report += "- SSL certificate is valid.\n" if cert_valid else "- SSL certificate is invalid or expired.\n"
    if email_check:
        report += "- Email header has inconsistencies (potential spoofing).\n"
    return report

# Function to save the phishing report to a file
def save_report(report, filename="phishing_report.txt"):
    with open(filename, "a") as file:
        file.write(report + "\n")
    print(f"Report saved to {filename}")

# Function to read URLs from a batch file
def get_urls_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            urls = [line.strip() for line in file.readlines()]
        return urls
    except Exception as e:
        print(f"Error reading batch file: {e}")
        return []

# Function for batch URL analysis
def batch_url_analysis(file_path):
    urls = get_urls_from_file(file_path)
    for url in urls:
        print(f"\nAnalyzing {url}...")
        analyze_url(url)
        rate_limit()

# Function to handle VirusTotal rate limiting
def rate_limit():
    print(f"Rate limit reached. Waiting for {SLEEP_INTERVAL} seconds before making the next request...")
    time.sleep(SLEEP_INTERVAL)

# Function to analyze a single URL with color-coded output
def analyze_url(url):
    print(f"Analyzing URL: {url}")

    # URL Pattern Check
    if is_suspicious_url(url):
        print(Fore.RED + "Warning: URL has suspicious patterns.")
    
    # SSL Certificate Check using requests
    cert_valid = False
    try:
        cert_valid = check_ssl_certificate(url)
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error connecting to {url}: {e}")
        cert_valid = None  # Set to None if there's a connection error
    
    # VirusTotal API Check with Rate Limiting
    if cert_valid is not None:
        is_blacklisted, positives = check_url_virustotal(url)
        if is_blacklisted:
            print(Fore.RED + f"URL is blacklisted with {positives} detections.")
        else:
            print(Fore.GREEN + "URL is safe.")
    else:
        print(Fore.RED + "Skipping VirusTotal check due to SSL/connection issue.")
        is_blacklisted = False  # Skipping the blacklisting check

    # Generate and print report
    if cert_valid is None:
        report = f"Phishing Detection Report for {url}:\n- DNS resolution failed.\n"
    else:
        report = generate_report(url, is_blacklisted, cert_valid, False)

    print(report)
    save_report(report)

# Parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Phishing Detection Tool with Batch Processing and Email Header Analysis")
    parser.add_argument('-u', '--url', help="URL to analyze for phishing patterns")
    parser.add_argument('-e', '--email', help="Analyze email headers for phishing", action='store_true')
    parser.add_argument('--batch', help="Path to file containing URLs for batch analysis")
    return parser.parse_args()

# Main function
def main():
    args = parse_arguments()

    if args.email:
        email_header = get_email_header()
        spf_valid, email_check = analyze_email_header(email_header)
        print(f"SPF Valid: {spf_valid}, Email Check: {email_check}")
    elif args.batch:
        batch_url_analysis(args.batch)
    elif args.url:
        analyze_url(args.url)
    else:
        print("Please provide either a URL or an email header for analysis.")

if __name__ == "__main__":
    main()
