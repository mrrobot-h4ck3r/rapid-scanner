#!/usr/bin/env python3
"""
Single Domain Recon Script
- Finds JS files, admin portals, open redirects
- No external dependencies beyond requests
- Runs in 1-2 minutes per domain
"""
import re
import json
import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

class RapidScanner:
    def __init__(self, domain):
        self.domain = domain
        self.base_urls = [f"http://{domain}", f"https://{domain}"]
        self.session = requests.Session()
        self.session.headers = {'User-Agent': 'Mozilla/5.0'}
        self.found = {
            'js_files': [],
            'admin_pages': [],
            'open_redirects': [],
            'config_files': []
        }

    def scan(self):
        """Run all scans"""
        urls = self.discover_urls()
        self.check_urls(urls)
        return self.found

    def discover_urls(self):
        """Find URLs to scan"""
        urls = set()
        
        # Check common paths
        common_paths = [
            '', 'admin', 'login', 'api', 'dashboard',
            'config.js', 'settings.php', '.env'
        ]
        
        for path in common_paths:
            urls.update(f"{base}/{path}" for base in self.base_urls)
        
        # Find links from homepage
        for base in self.base_urls:
            try:
                resp = self.session.get(base, timeout=10)
                urls.update(urljoin(base, u) for u in 
                           re.findall(r'href=[\'"]?([^\'" >]+)', resp.text))
            except:
                continue
        
        return list(urls)

    def check_urls(self, urls):
        """Scan multiple URLs in parallel"""
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(self.check_url, url) for url in urls]
            for future in futures:
                result = future.result()
                if result:
                    self.found[result[0]].append(result[1])

    def check_url(self, url):
        """Scan single URL"""
        try:
            resp = self.session.get(url, timeout=8, allow_redirects=False)
            
            # Check for JS files
            if re.search(r'\.js(\?|$)', url, re.I) and resp.status_code == 200:
                return ('js_files', url)
                
            # Check for admin portals
            if (re.search(r'(admin|dashboard)', url, re.I) 
                and resp.status_code == 200):
                return ('admin_pages', url)
                
            # Check for open redirects
            if 300 <= resp.status_code < 400:
                loc = resp.headers.get('location', '')
                if any(x in loc for x in ['http://', 'https://']):
                    return ('open_redirects', f"{url} → {loc}")
                    
            # Check for config files
            if re.search(r'(config|setting|env)\.(json|js|php)', url, re.I):
                return ('config_files', url)
                
        except:
            pass
        return None

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        sys.exit(1)
    
    domain = sys.argv[1].strip()
    print(f"[*] Scanning {domain}...")
    
    scanner = RapidScanner(domain)
    results = scanner.scan()
    
    output_file = f"{domain}_scan.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"[+] Results saved to {output_file}")
    print("\nCritical Findings:")
    for category, items in results.items():
        if items:
            print(f"\n{category.upper()}:")
            for item in items:
                print(f"  - {item}")
