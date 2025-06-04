import requests
import urllib.parse
from urllib.robotparser import RobotFileParser
from bs4 import BeautifulSoup
import re
import socket
import ssl
import datetime
import json
import argparse
import sys
from collections import defaultdict
import time
import random # Import for randomization

class WebScanner:
    def __init__(self, target_url, max_pages=10, delay_range=(1, 5)): # Modified delay to be a range
        self.target_url = target_url.rstrip('/')
        self.domain = urllib.parse.urlparse(target_url).netloc
        self.max_pages = max_pages
        self.delay_range = delay_range # Store delay as a range
        self.session = requests.Session()
        
        # List of common User-Agents to rotate
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.112 Mobile Safari/537.36"
        ]

        self.accept_headers = [
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        ]
        self.accept_language_headers = [
            "en-US,en;q=0.5",
            "en-GB,en;q=0.9",
            "en-CA,en;q=0.8"
        ]
        self.accept_encoding_headers = [
            "gzip, deflate, br",
            "gzip, deflate",
            "deflate"
        ]

        self.results = {
            'scan_info': {},
            'ssl_info': {},
            'headers': {},
            'technologies': set(),
            'pages': [],
            'links': set(),
            'forms': [],
            'robots_txt': '',
            'sitemap': [],
            'cookies': [],
            'security_analysis': {}
        }
        self.robot_parser = RobotFileParser() # Initialize robot parser
        self.last_crawled_url = None # To track referer

    def scan(self):
        """Main scanning function"""
        print(f"Starting passive scan of {self.target_url}")
        
        # Basic scan info
        self.results['scan_info'] = {
            'target': self.target_url,
            'domain': self.domain,
            'timestamp': datetime.datetime.now().isoformat(),
            'max_pages': self.max_pages
        }
        
        # SSL/TLS Analysis
        self._analyze_ssl()
        
        # Robots.txt analysis
        self._analyze_robots()
        
        # Main page analysis
        self._scan_page(self.target_url)
        
        # Crawl additional pages
        self._crawl_pages()
        
        # Security analysis
        self._security_analysis()
        
        print(f"Scan completed. Found {len(self.results['pages'])} pages")
        return self.results
    
    def _analyze_ssl(self):
        """Analyze SSL/TLS configuration"""
        try:
            parsed = urllib.parse.urlparse(self.target_url)
            if parsed.scheme == 'https':
                context = ssl.create_default_context()
                with socket.create_connection((self.domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        cert = ssock.getpeercert()
                        self.results['ssl_info'] = {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'version': cert['version'],
                            'serial_number': cert['serialNumber'],
                            'not_before': cert['notBefore'],
                            'not_after': cert['notAfter'],
                            'protocol': ssock.version()
                        }
        except Exception as e:
            self.results['ssl_info'] = {'error': str(e)}
    
    def _analyze_robots(self):
        """Analyze robots.txt file and prepare robot_parser"""
        try:
            robots_url = f"{self.target_url}/robots.txt"
            response = self.session.get(robots_url, timeout=10)
            if response.status_code == 200:
                self.results['robots_txt'] = response.text
                self.robot_parser.parse(response.text.splitlines()) # Parse robots.txt
                
                # Parse sitemap URLs from robots.txt
                for line in response.text.split('\n'):
                    if line.lower().startswith('sitemap:'):
                        sitemap_url = line.split(':', 1)[1].strip()
                        self.results['sitemap'].append(sitemap_url)
            else:
                self.results['robots_txt'] = f"No robots.txt found or error: Status {response.status_code}"
        except Exception as e:
            self.results['robots_txt'] = f"Error fetching robots.txt: {str(e)}"
            
    def _scan_page(self, url, referer=None, attempt=0):
        """Scan individual page with stealth features and retry logic"""
        if not self.robot_parser.can_fetch("*", url): # Check robots.txt
            print(f"Skipping {url} due to robots.txt Disallow rule.")
            return

        try:
            print(f"Scanning: {url}")
            headers = {
                'User-Agent': random.choice(self.user_agents),
                'Accept': random.choice(self.accept_headers),
                'Accept-Language': random.choice(self.accept_language_headers),
                'Accept-Encoding': random.choice(self.accept_encoding_headers),
            }
            if referer:
                headers['Referer'] = referer
            
            response = self.session.get(url, headers=headers, timeout=15, allow_redirects=True) # Increased timeout
            
            # Retry mechanism for transient errors
            if response.status_code in [429, 500, 502, 503, 504] and attempt < 3: # Retry up to 3 times
                retry_delay = 2 ** attempt + random.uniform(0, 1) # Exponential backoff
                print(f"Received status {response.status_code} for {url}. Retrying in {retry_delay:.2f} seconds...")
                time.sleep(retry_delay)
                self._scan_page(url, referer, attempt + 1)
                return
            
            self.last_crawled_url = url # Update last crawled URL for Referer header

            page_info = {
                'url': url,
                'status_code': response.status_code,
                'final_url': response.url,
                'headers': dict(response.headers),
                'title': '',
                'meta_tags': {},
                'forms': [],
                'links': [],
                'scripts': [],
                'stylesheets': [],
                'images': [],
                'technologies': set()
            }
            
            # Store response headers for analysis (only if it's the first page or a main page)
            if not self.results['headers'] or url == self.target_url:
                self.results['headers'] = dict(response.headers)
            
            # Store cookies
            for cookie in response.cookies:
                cookie_info = {
                    'name': cookie.name,
                    'value': cookie.value,
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'secure': cookie.secure,
                    'httponly': getattr(cookie, 'httponly', False)
                }
                self.results['cookies'].append(cookie_info)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract title
                title_tag = soup.find('title')
                if title_tag:
                    page_info['title'] = title_tag.get_text().strip()
                
                # Extract meta tags
                for meta in soup.find_all('meta'):
                    name = meta.get('name') or meta.get('property') or meta.get('http-equiv')
                    content = meta.get('content')
                    if name and content:
                        page_info['meta_tags'][name] = content
                
                # Extract forms
                for form in soup.find_all('form'):
                    form_info = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET').upper(),
                        'inputs': []
                    }
                    
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        input_info = {
                            'type': input_tag.get('type', 'text'),
                            'name': input_tag.get('name', ''),
                            'id': input_tag.get('id', '')
                        }
                        form_info['inputs'].append(input_info)
                    
                    page_info['forms'].append(form_info)
                    self.results['forms'].append(form_info)
                
                # Extract links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    absolute_url = urllib.parse.urljoin(url, href)
                    page_info['links'].append(absolute_url)
                    
                    # Add internal links to crawl queue
                    if self._is_internal_link(absolute_url):
                        self.results['links'].add(absolute_url)
                
                # Extract scripts
                for script in soup.find_all('script', src=True):
                    page_info['scripts'].append(script['src'])
                
                # Extract stylesheets
                for link in soup.find_all('link', rel='stylesheet'):
                    if link.get('href'):
                        page_info['stylesheets'].append(link['href'])
                
                # Extract images
                for img in soup.find_all('img', src=True):
                    page_info['images'].append(img['src'])
                
                # Technology detection
                self._detect_technologies(response, soup, page_info)
            
            self.results['pages'].append(page_info)
            
        except requests.exceptions.RequestException as req_e:
            error_page = {
                'url': url,
                'error': f"Request Error: {str(req_e)}",
                'status_code': 'Connection Error'
            }
            self.results['pages'].append(error_page)
        except Exception as e:
            error_page = {
                'url': url,
                'error': f"Processing Error: {str(e)}",
                'status_code': 'Error'
            }
            self.results['pages'].append(error_page)
    
    def _detect_technologies(self, response, soup, page_info):
        """Detect technologies used on the website"""
        technologies = set()
        
        # Server header
        server = response.headers.get('Server', '')
        if server:
            technologies.add(f"Server: {server}")
        
        # X-Powered-By header
        powered_by = response.headers.get('X-Powered-By', '')
        if powered_by:
            technologies.add(f"Framework: {powered_by}")
        
        # Meta generator
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and generator.get('content'):
            technologies.add(f"CMS: {generator['content']}")
        
        # Common JavaScript libraries
        scripts = [script.get('src', '') for script in soup.find_all('script') if script.get('src')]
        script_text = ' '.join([script.get_text() for script in soup.find_all('script')])
        
        js_libraries = {
            'jQuery': ['jquery', 'jQuery'],
            'React': ['react.js', 'react.min.js', 'React'],
            'Angular': ['angular.js', 'angular.min.js', 'ng-'],
            'Vue.js': ['vue.js', 'vue.min.js', 'Vue'],
            'Bootstrap': ['bootstrap.js', 'bootstrap.min.js'],
            'Drupal': ['Drupal.'],
            'WordPress': ['wp-content', 'wp-includes']
        }
        
        for lib, patterns in js_libraries.items():
            for pattern in patterns:
                if any(pattern in script for script in scripts) or pattern in script_text:
                    technologies.add(f"JavaScript: {lib}")
                    break
        
        # CSS frameworks
        stylesheets = [link.get('href', '') for link in soup.find_all('link', rel='stylesheet')]
        
        css_frameworks = {
            'Bootstrap': ['bootstrap.css', 'bootstrap.min.css'],
            'Foundation': ['foundation.css', 'foundation.min.css'],
            'Materialize': ['materialize.css', 'materialize.min.css']
        }
        
        for framework, patterns in css_frameworks.items():
            for pattern in patterns:
                if any(pattern in sheet for sheet in stylesheets):
                    technologies.add(f"CSS: {framework}")
                    break
        
        page_info['technologies'] = technologies
        self.results['technologies'].update(technologies)
    
    def _is_internal_link(self, url):
        """Check if link is internal to the target domain"""
        try:
            parsed = urllib.parse.urlparse(url)
            # Only consider http/https links as internal for crawling purposes
            if parsed.scheme not in ['http', 'https']:
                return False
            return parsed.netloc == self.domain or parsed.netloc == ''
        except:
            return False
    
    def _crawl_pages(self):
        """Crawl additional pages found in links"""
        crawled = {self.target_url}
        # Convert set to list to allow slicing, prioritize recently found links
        to_crawl = list(self.results['links']) 
        random.shuffle(to_crawl) # Randomize crawl order for stealth
        to_crawl = to_crawl[:self.max_pages - len(self.results['pages'])] # Adjust based on already scanned pages
        
        for url in to_crawl:
            if url not in crawled and len(self.results['pages']) < self.max_pages:
                time.sleep(random.uniform(*self.delay_range)) # Randomized delay
                self._scan_page(url, referer=self.last_crawled_url) # Pass referer
                crawled.add(url)
    
    def _security_analysis(self):
        """Perform comprehensive security analysis with risk scoring"""
        security = {}
        headers = self.results['headers']
        
        # Initialize risk assessment
        risk_assessment = {
            'overall_score': 0,
            'risk_level': 'LOW',
            'total_issues': 0,
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'low_issues': 0,
            'owasp_findings': {},
            'nist_compliance': {},
            'recommendations': []
        }
        
        # OWASP Top 10 2021 Assessment
        owasp_checks = self._owasp_top10_assessment(headers)
        risk_assessment['owasp_findings'] = owasp_checks
        
        # Security headers analysis with scoring
        security_headers_analysis = self._analyze_security_headers(headers)
        security['security_headers'] = security_headers_analysis['headers']
        
        # Cookie security analysis with scoring
        cookie_analysis = self._analyze_cookies_security()
        security['cookie_analysis'] = cookie_analysis['analysis']
        
        # Form security analysis with scoring
        form_analysis = self._analyze_forms_security()
        security['form_analysis'] = form_analysis['analysis']
        
        # SSL/TLS security analysis with scoring
        ssl_analysis = self._analyze_ssl_security()
        
        # Information disclosure analysis
        info_disclosure = self._analyze_information_disclosure(headers)
        
        # Calculate overall risk score
        risk_components = [
            owasp_checks['total_score'],
            security_headers_analysis['score'],
            cookie_analysis['score'],
            form_analysis['score'],
            ssl_analysis['score'],
            info_disclosure['score']
        ]
        
        # Risk scoring calculation (0-100, lower is better)
        total_possible_score = 600  # 6 components * 100 max each
        actual_score = sum(risk_components)
        risk_percentage = (actual_score / total_possible_score) * 100
        
        # Determine risk level
        if risk_percentage >= 75:
            risk_level = 'CRITICAL'
        elif risk_percentage >= 50:
            risk_level = 'HIGH'
        elif risk_percentage >= 25:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        risk_assessment.update({
            'overall_score': round(risk_percentage, 1),
            'risk_level': risk_level,
            'component_scores': {
                'owasp_compliance': 100 - round((owasp_checks['total_score'] / 100) * 100, 1),
                'security_headers': 100 - round((security_headers_analysis['score'] / 100) * 100, 1),
                'cookie_security': 100 - round((cookie_analysis['score'] / 100) * 100, 1),
                'form_security': 100 - round((form_analysis['score'] / 100) * 100, 1),
                'ssl_tls_security': 100 - round((ssl_analysis['score'] / 100) * 100, 1),
                'information_disclosure': 100 - round((info_disclosure['score'] / 100) * 100, 1)
            }
        })
        
        # Generate recommendations
        risk_assessment['recommendations'] = self._generate_security_recommendations(
            owasp_checks, security_headers_analysis, cookie_analysis, 
            form_analysis, ssl_analysis, info_disclosure
        )
        
        security['risk_assessment'] = risk_assessment
        security['ssl_security'] = ssl_analysis
        security['information_disclosure'] = info_disclosure
        
        self.results['security_analysis'] = security
    
    def _owasp_top10_assessment(self, headers):
        """Assess against OWASP Top 10 2021"""
        findings = {}
        total_score = 0
        
        # A01:2021 – Broken Access Control
        access_control_score = 0
        access_control_issues = []
        
        # Check for basic access control headers
        if 'X-Frame-Options' not in headers and 'Content-Security-Policy' not in headers:
            access_control_score += 20
            access_control_issues.append("Missing clickjacking protection")
        
        findings['A01_Broken_Access_Control'] = {
            'score': access_control_score,
            'risk_level': 'HIGH' if access_control_score >= 15 else 'MEDIUM' if access_control_score >= 5 else 'LOW',
            'issues': access_control_issues
        }
        
        # A02:2021 – Cryptographic Failures
        crypto_score = 0
        crypto_issues = []
        
        if not self.target_url.startswith('https'):
            crypto_score += 30
            crypto_issues.append("Site not using HTTPS")
        
        if 'Strict-Transport-Security' not in headers and self.target_url.startswith('https'):
            crypto_score += 15
            crypto_issues.append("HSTS not implemented")
        
        findings['A02_Cryptographic_Failures'] = {
            'score': crypto_score,
            'risk_level': 'CRITICAL' if crypto_score >= 25 else 'HIGH' if crypto_score >= 15 else 'MEDIUM' if crypto_score >= 5 else 'LOW',
            'issues': crypto_issues
        }
        
        # A03:2021 – Injection
        injection_score = 0
        injection_issues = []
        
        if 'Content-Security-Policy' not in headers:
            injection_score += 20
            injection_issues.append("No Content Security Policy to prevent injection attacks")
        
        if 'X-Content-Type-Options' not in headers:
            injection_score += 10
            injection_issues.append("Missing MIME type sniffing protection")
        
        findings['A03_Injection'] = {
            'score': injection_score,
            'risk_level': 'HIGH' if injection_score >= 20 else 'MEDIUM' if injection_score >= 10 else 'LOW',
            'issues': injection_issues
        }
        
        # A04:2021 – Insecure Design
        design_score = 0
        design_issues = []
        
        # Check for security headers that indicate secure design
        security_headers_count = sum(1 for h in ['Content-Security-Policy', 'X-Frame-Options', 
                                                 'X-Content-Type-Options', 'Referrer-Policy'] if h in headers)
        if security_headers_count < 2:
            design_score += 15
            design_issues.append("Insufficient security headers implementation")
        
        findings['A04_Insecure_Design'] = {
            'score': design_score,
            'risk_level': 'MEDIUM' if design_score >= 10 else 'LOW',
            'issues': design_issues
        }
        
        # A05:2021 – Security Misconfiguration
        misconfig_score = 0
        misconfig_issues = []
        
        server_header = headers.get('Server', '')
        if server_header and any(version in server_header.lower() for version in ['apache/2.2', 'nginx/1.1', 'iis/7']):
            misconfig_score += 15
            misconfig_issues.append(f"Potentially outdated server version disclosed: {server_header}")
        
        if 'X-Powered-By' in headers:
            misconfig_score += 10
            misconfig_issues.append("Technology disclosure in X-Powered-By header")
        
        findings['A05_Security_Misconfiguration'] = {
            'score': misconfig_score,
            'risk_level': 'MEDIUM' if misconfig_score >= 15 else 'LOW',
            'issues': misconfig_issues
        }
        
        # A06:2021 – Vulnerable and Outdated Components
        components_score = 0
        components_issues = []
        
        # This would require more sophisticated analysis of detected technologies
        outdated_indicators = ['jquery/1.', 'bootstrap/3.', 'angular/1.']
        for tech in self.results['technologies']:
            for indicator in outdated_indicators:
                if indicator in tech.lower():
                    components_score += 10
                    components_issues.append(f"Potentially outdated component detected: {tech}")
        
        findings['A06_Vulnerable_Outdated_Components'] = {
            'score': components_score,
            'risk_level': 'HIGH' if components_score >= 20 else 'MEDIUM' if components_score >= 10 else 'LOW',
            'issues': components_issues
        }
        
        # A07:2021 – Identification and Authentication Failures
        auth_score = 0
        auth_issues = []
        
        # Check for insecure cookie settings (affects session management)
        insecure_cookies = sum(1 for cookie in self.results['cookies'] 
                               if not cookie.get('secure') or not cookie.get('httponly'))
        if insecure_cookies > 0:
            auth_score += insecure_cookies * 5
            auth_issues.append(f"{insecure_cookies} cookies with security issues")
        
        findings['A07_Identification_Authentication_Failures'] = {
            'score': min(auth_score, 25),  # Cap at 25
            'risk_level': 'HIGH' if auth_score >= 20 else 'MEDIUM' if auth_score >= 10 else 'LOW',
            'issues': auth_issues
        }
        
        # A08:2021 – Software and Data Integrity Failures
        integrity_score = 0
        integrity_issues = []
        
        if 'Content-Security-Policy' not in headers:
            integrity_score += 15
            integrity_issues.append("No CSP to protect against data integrity attacks")
        
        findings['A08_Software_Data_Integrity_Failures'] = {
            'score': integrity_score,
            'risk_level': 'MEDIUM' if integrity_score >= 10 else 'LOW',
            'issues': integrity_issues
        }
        
        # A09:2021 – Security Logging and Monitoring Failures
        logging_score = 10  # Default penalty as we can't easily detect this
        logging_issues = ["Cannot assess logging and monitoring capabilities remotely"]
        
        findings['A09_Security_Logging_Monitoring_Failures'] = {
            'score': logging_score,
            'risk_level': 'MEDIUM',
            'issues': logging_issues
        }
        
        # A10:2021 – Server-Side Request Forgery (SSRF)
        ssrf_score = 5  # Default low score as this requires deep testing
        ssrf_issues = ["SSRF vulnerabilities require detailed application testing"]
        
        findings['A10_Server_Side_Request_Forgery'] = {
            'score': ssrf_score,
            'risk_level': 'LOW',
            'issues': ssrf_issues
        }
        
        total_score = sum(finding['score'] for finding in findings.values())
        
        return {
            'findings': findings,
            'total_score': total_score,
            'max_possible_score': 100
        }
    
    def _analyze_security_headers(self, headers):
        """Analyze security headers with scoring"""
        security_headers = {
            'Strict-Transport-Security': {'weight': 15, 'description': 'HSTS protection'},
            'Content-Security-Policy': {'weight': 20, 'description': 'Content injection protection'},
            'X-Frame-Options': {'weight': 15, 'description': 'Clickjacking protection'},
            'X-Content-Type-Options': {'weight': 10, 'description': 'MIME sniffing protection'},
            'X-XSS-Protection': {'weight': 10, 'description': 'XSS protection'},
            'Referrer-Policy': {'weight': 5, 'description': 'Referrer information control'},
            'Permissions-Policy': {'weight': 10, 'description': 'Feature policy control'},
            'Cross-Origin-Embedder-Policy': {'weight': 5, 'description': 'Cross-origin embedding control'},
            'Cross-Origin-Opener-Policy': {'weight': 5, 'description': 'Cross-origin opener control'},
            'Cross-Origin-Resource-Policy': {'weight': 5, 'description': 'Cross-origin resource control'}
        }
        
        analysis = {}
        score = 0
        
        for header, config in security_headers.items():
            if header in headers:
                analysis[header] = {
                    'status': 'Present',
                    'value': headers[header],
                    'risk_level': 'LOW'
                }
            else:
                analysis[header] = {
                    'status': f'Missing - {config["description"]} not implemented',
                    'value': 'Not Set',
                    'risk_level': 'HIGH' if config['weight'] >= 15 else 'MEDIUM'
                }
                score += config['weight']
        
        return {'headers': analysis, 'score': score}
    
    def _analyze_cookies_security(self):
        """Analyze cookie security with scoring"""
        analysis = []
        score = 0
        
        for cookie in self.results['cookies']:
            issues = []
            cookie_score = 0
            
            if not cookie.get('secure') and self.target_url.startswith('https'):
                issues.append('Missing Secure flag')
                cookie_score += 10
            
            if not cookie.get('httponly'):
                issues.append('Missing HttpOnly flag')
                cookie_score += 10
            
            # Check for SameSite attribute (not easily detectable in basic scan)
            if 'samesite' not in str(cookie).lower():
                issues.append('SameSite attribute not detected')
                cookie_score += 5
            
            analysis.append({
                'name': cookie['name'],
                'issues': issues if issues else ['No issues found'],
                'risk_level': 'HIGH' if cookie_score >= 20 else 'MEDIUM' if cookie_score >= 10 else 'LOW'
            })
            
            score += cookie_score
        
        return {'analysis': analysis, 'score': min(score, 50)}  # Cap at 50
    
    def _analyze_forms_security(self):
        """Analyze form security with scoring"""
        analysis = []
        score = 0
        
        for form in self.results['forms']:
            issues = []
            form_score = 0
            
            if form['method'] == 'GET' and any(inp['type'] == 'password' for inp in form['inputs']):
                issues.append('Password field in GET form')
                form_score += 20
            
            if not form['action'].startswith('https') and self.target_url.startswith('https'):
                issues.append('Form action not using HTTPS')
                form_score += 15
            
            # Check for CSRF protection (basic check for token fields)
            has_csrf_token = any(
                'csrf' in inp.get('name', '').lower() or 
                'token' in inp.get('name', '').lower() or
                inp.get('type') == 'hidden'
                for inp in form['inputs']
            )
            
            if not has_csrf_token and form['method'] == 'POST':
                issues.append('Possible missing CSRF protection')
                form_score += 10
            
            analysis.append({
                'action': form['action'] or 'Current page',
                'method': form['method'],
                'issues': issues if issues else ['No obvious issues found'],
                'risk_level': 'HIGH' if form_score >= 20 else 'MEDIUM' if form_score >= 10 else 'LOW'
            })
            
            score += form_score
        
        return {'analysis': analysis, 'score': min(score, 40)}  # Cap at 40
    
    def _analyze_ssl_security(self):
        """Analyze SSL/TLS security with scoring"""
        score = 0
        issues = []
        
        if not self.target_url.startswith('https'):
            score += 50
            issues.append('Site not using HTTPS')
        elif 'error' in self.results['ssl_info']:
            score += 30
            issues.append('SSL certificate issues detected')
        else:
            ssl_info = self.results['ssl_info']
            
            # Check certificate validity period (simplified for demonstration)
            # In a real scenario, you'd parse 'not_after' and compare to datetime.now()
            # For brevity, this example just checks for existence.
            if not ssl_info.get('not_after'):
                issues.append('SSL certificate validity period not available')
                score += 5
            
            # Check for weak protocols (if detectable)
            protocol = ssl_info.get('protocol', '')
            if 'TLSv1.0' in protocol or 'TLSv1.1' in protocol or 'SSLv' in protocol:
                score += 20
                issues.append(f'Weak SSL/TLS protocol: {protocol}')
        
        return {
            'score': score,
            'issues': issues if issues else ['SSL/TLS configuration appears secure'],
            'risk_level': 'CRITICAL' if score >= 40 else 'HIGH' if score >= 20 else 'MEDIUM' if score >= 10 else 'LOW'
        }
    
    def _analyze_information_disclosure(self, headers):
        """Analyze information disclosure risks"""
        score = 0
        issues = []
        
        # Check for information disclosure in headers
        disclosure_headers = {
            'Server': 'Server version information disclosed',
            'X-Powered-By': 'Technology stack information disclosed',
            'X-AspNet-Version': 'ASP.NET version disclosed',
            'X-AspNetMvc-Version': 'ASP.NET MVC version disclosed'
        }
        
        for header, description in disclosure_headers.items():
            if header in headers:
                score += 5
                issues.append(f"{description}: {headers[header]}")
        
        # Check for detailed error pages (would need content analysis)
        # This is a placeholder for more sophisticated analysis
        
        return {
            'score': score,
            'issues': issues if issues else ['No obvious information disclosure'],
            'risk_level': 'MEDIUM' if score >= 15 else 'LOW'
        }
    
    def _generate_security_recommendations(self, owasp, headers_analysis, cookies, forms, ssl, info_disclosure):
        """Generate prioritized security recommendations"""
        recommendations = []
        
        # Critical recommendations
        if ssl['score'] >= 30:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'SSL/TLS',
                'issue': 'Implement HTTPS',
                'description': 'The website is not using HTTPS encryption, exposing all data in transit.',
                'remediation': 'Obtain and install an SSL certificate and redirect all HTTP traffic to HTTPS.'
            })
        
        # High priority recommendations
        if 'Content-Security-Policy' not in self.results['headers']:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Injection Protection',
                'issue': 'Implement Content Security Policy',
                'description': 'Missing CSP leaves the site vulnerable to XSS and injection attacks.',
                'remediation': 'Implement a restrictive Content-Security-Policy header.'
            })
        
        if 'Strict-Transport-Security' not in self.results['headers'] and self.target_url.startswith('https'):
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Transport Security',
                'issue': 'Implement HSTS',
                'description': 'Missing HSTS header allows potential downgrade attacks.',
                'remediation': 'Add Strict-Transport-Security header with appropriate max-age.'
            })
        
        # Medium priority recommendations
        if 'X-Frame-Options' not in self.results['headers']:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Clickjacking Protection',
                'issue': 'Implement X-Frame-Options',
                'description': 'Missing clickjacking protection.',
                'remediation': 'Add X-Frame-Options: DENY or SAMEORIGIN header.'
            })
        
        if cookies['score'] > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Cookie Security',
                'issue': 'Secure cookie configuration',
                'description': 'Cookies are missing security attributes.',
                'remediation': 'Add Secure, HttpOnly, and SameSite attributes to all cookies.'
            })
        
        # Low priority recommendations
        missing_headers = [h for h, data in headers_analysis['headers'].items() 
                           if data['status'] != 'Present' and h not in ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options']]
        
        if missing_headers:
            recommendations.append({
                'priority': 'LOW',
                'category': 'Security Headers',
                'issue': 'Additional security headers',
                'description': f'Missing security headers: {", ".join(missing_headers[:3])}',
                'remediation': 'Implement additional security headers for defense in depth.'
            })
        
        return recommendations
    
    def generate_html_report(self, output_file): # output_file is now mandatory
        """Generate HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Scanner Report - {domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1, h2, h3 {{ color: #333; }}
        h1 {{ border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ background-color: #007bff; color: white; padding: 10px; margin: 20px 0 10px 0; border-radius: 5px; }}
        h3 {{ color: #007bff; border-left: 4px solid #007bff; padding-left: 10px; }}
        .info-box {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #007bff; }}
        .warning-box {{ background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #ffc107; }}
        .error-box {{ background-color: #f8d7da; padding: 15px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #dc3545; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #007bff; color: white; }}
        tr:nth-child(even) {{ background-color: #f8f9fa; }}
        .tech-tag {{ display: inline-block; background-color: #e9ecef; padding: 3px 8px; margin: 2px; border-radius: 12px; font-size: 12px; }}
        .status-200 {{ color: #28a745; font-weight: bold; }}
        .status-404 {{ color: #dc3545; font-weight: bold; }}
        .status-other {{ color: #ffc107; font-weight: bold; }}
        pre {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .toc {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .toc ul {{ list-style-type: none; padding-left: 0; }}
        .toc li {{ margin: 5px 0; }}
        .toc a {{ text-decoration: none; color: #007bff; }}
        .toc a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Web Scanner Report</h1>
        
        <div class="info-box">
            <strong>Target:</strong> {target}<br>
            <strong>Domain:</strong> {domain}<br>
            <strong>Scan Date:</strong> {timestamp}<br>
            <strong>Pages Scanned:</strong> {pages_count}
        </div>

        <div class="toc">
            <h3>📋 Table of Contents</h3>
            <ul>
                <li><a href="#ssl-info">🔒 SSL/TLS Information</a></li>
                <li><a href="#technologies">⚙️ Technologies Detected</a></li>
                <li><a href="#security-analysis">🛡️ Security Analysis</a></li>
                <li><a href="#pages-info">📄 Pages Information</a></li>
                <li><a href="#forms-info">📝 Forms Analysis</a></li>
                <li><a href="#headers-info">📨 HTTP Headers</a></li>
                <li><a href="#robots-info">🤖 Robots.txt</a></li>
            </ul>
        </div>

        <h2 id="ssl-info">🔒 SSL/TLS Information</h2>
        {ssl_section}

        <h2 id="technologies">⚙️ Technologies Detected</h2>
        <div class="info-box">
            {technologies_section}
        </div>

        <h2 id="security-analysis">🛡️ Security Analysis</h2>
        {security_section}

        <h2 id="pages-info">📄 Pages Information</h2>
        {pages_section}

        <h2 id="forms-info">📝 Forms Analysis</h2>
        {forms_section}

        <h2 id="headers-info">📨 HTTP Headers</h2>
        {headers_section}

        <h2 id="robots-info">🤖 Robots.txt</h2>
        <pre>{robots_content}</pre>

        <hr style="margin: 40px 0;">
        <p style="text-align: center; color: #666; font-size: 12px;">
            Report generated by Web Scanner on {timestamp}
        </p>
    </div>
</body>
</html>
        """
        
        # Generate sections
        ssl_section = self._generate_ssl_section()
        technologies_section = self._generate_technologies_section()
        security_section = self._generate_security_section()
        pages_section = self._generate_pages_section()
        forms_section = self._generate_forms_section()
        headers_section = self._generate_headers_section()
        
        # Fill template
        html_content = html_template.format(
            domain=self.results['scan_info']['domain'],
            target=self.results['scan_info']['target'],
            timestamp=self.results['scan_info']['timestamp'],
            pages_count=len(self.results['pages']),
            ssl_section=ssl_section,
            technologies_section=technologies_section,
            security_section=security_section,
            pages_section=pages_section,
            forms_section=forms_section,
            headers_section=headers_section,
            robots_content=self.results['robots_txt']
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"HTML report generated: {output_file}")
    
    def _generate_ssl_section(self):
        ssl_info = self.results['ssl_info']
        if 'error' in ssl_info:
            return f'<div class="error-box">SSL Analysis failed: {ssl_info["error"]}</div>'
        
        if not ssl_info:
            return '<div class="info-box">No SSL information available (HTTP site)</div>'
        
        return f"""
        <div class="info-box">
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td><strong>Subject</strong></td><td>{ssl_info.get('subject', {}).get('commonName', 'N/A')}</td></tr>
                <tr><td><strong>Issuer</strong></td><td>{ssl_info.get('issuer', {}).get('organizationName', 'N/A')}</td></tr>
                <tr><td><strong>Valid From</strong></td><td>{ssl_info.get('not_before', 'N/A')}</td></tr>
                <tr><td><strong>Valid Until</strong></td><td>{ssl_info.get('not_after', 'N/A')}</td></tr>
                <tr><td><strong>Protocol</strong></td><td>{ssl_info.get('protocol', 'N/A')}</td></tr>
            </table>
        </div>
        """
    
    def _generate_technologies_section(self):
        if not self.results['technologies']:
            return '<p>No technologies detected</p>'
        
        return ''.join([f'<span class="tech-tag">{tech}</span>' for tech in sorted(self.results['technologies'])])
    
    def _generate_security_section(self):
        security = self.results['security_analysis']
        risk_assessment = security.get('risk_assessment', {})
        
        # Risk overview section
        risk_level = risk_assessment.get('risk_level', 'UNKNOWN')
        risk_score = risk_assessment.get('overall_score', 0)
        
        risk_color = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14', 
            'MEDIUM': '#ffc107',
            'LOW': '#28a745'
        }.get(risk_level, '#6c757d')
        
        section = f'''
        <div class="risk-overview" style="background: linear-gradient(135deg, {risk_color}22, {risk_color}11); 
             border: 2px solid {risk_color}; border-radius: 10px; padding: 20px; margin: 20px 0;">
            <h3 style="color: {risk_color}; margin-top: 0;">🛡️ Security Risk Assessment</h3>
            <div style="display: flex; align-items: center; gap: 20px; margin: 15px 0;">
                <div style="font-size: 2.5em; font-weight: bold; color: {risk_color};">{risk_score}%</div>
                <div>
                    <div style="font-size: 1.2em; font-weight: bold; color: {risk_color};">Risk Level: {risk_level}</div>
                    <div style="color: #666;">Overall security posture assessment</div>
                </div>
            </div>
        </div>
        '''
        
        # Component scores
        if 'component_scores' in risk_assessment:
            section += '<h3>📊 Security Component Scores</h3>'
            section += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; margin: 20px 0;">'
            
            for component, score in risk_assessment['component_scores'].items():
                score_color = '#28a745' if score >= 80 else '#ffc107' if score >= 60 else '#fd7e14' if score >= 40 else '#dc3545'
                component_name = component.replace('_', ' ').title()
                
                section += f'''
                <div style="background: #f8f9fa; border-radius: 8px; padding: 15px; border-left: 4px solid {score_color};">
                    <div style="font-weight: bold; margin-bottom: 5px;">{component_name}</div>
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <div style="flex: 1; background: #e9ecef; border-radius: 10px; height: 10px;">
                            <div style="background: {score_color}; height: 100%; border-radius: 10px; width: {score}%;"></div>
                        </div>
                        <div style="font-weight: bold; color: {score_color};">{score:.1f}%</div>
                    </div>
                </div>
                '''
            section += '</div>'
        
        # OWASP Top 10 Assessment
        owasp_findings = risk_assessment.get('owasp_findings', {}).get('findings', {})
        if owasp_findings:
            section += '<h3>🔟 OWASP Top 10 2021 Assessment</h3>'
            section += '<table style="width: 100%; margin: 20px 0;"><tr><th style="width: 40%;">OWASP Category</th><th>Risk Level</th><th>Score</th><th>Issues Found</th></tr>'
            
            for category, data in owasp_findings.items():
                risk_level = data.get('risk_level', 'LOW')
                score = data.get('score', 0)
                issues = data.get('issues', [])
                
                risk_class = {
                    'CRITICAL': 'status-404',
                    'HIGH': 'status-404', 
                    'MEDIUM': 'status-other',
                    'LOW': 'status-200'
                }.get(risk_level, 'status-200')
                
                # Correcting OWASP category name formatting
                category_name = category.replace('_', ' ').replace('A0', 'A0').title()
                # Special handling for "A0" at the beginning of the category
                if category_name.startswith('A0'):
                    category_name = 'A0' + category_name[2:]


                issues_text = '; '.join(issues[:2]) if issues else 'No issues detected'
                if len(issues) > 2:
                    issues_text += f" (+{len(issues)-2} more)"
                
                section += f'''
                <tr>
                    <td><strong>{category_name}</strong></td>
                    <td><span class="{risk_class}">{risk_level}</span></td>
                    <td>{score}/25</td>
                    <td>{issues_text}</td>
                </tr>
                '''
            section += '</table>'
        
        # Security Recommendations
        recommendations = risk_assessment.get('recommendations', [])
        if recommendations:
            section += '<h3>💡 Security Recommendations</h3>'
            
            for priority in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                priority_recs = [r for r in recommendations if r.get('priority') == priority]
                if priority_recs:
                    priority_color = {
                        'CRITICAL': '#dc3545',
                        'HIGH': '#fd7e14',
                        'MEDIUM': '#ffc107', 
                        'LOW': '#28a745'
                    }.get(priority, '#6c757d')
                    
                    section += f'<h4 style="color: {priority_color}; margin-top: 25px;">🔸 {priority} Priority</h4>'
                    
                    for rec in priority_recs:
                        section += f'''
                        <div style="background: {priority_color}22; border-left: 4px solid {priority_color}; 
                             padding: 15px; margin: 10px 0; border-radius: 5px;">
                            <div style="font-weight: bold; color: {priority_color};">{rec.get('category', 'Security')}: {rec.get('issue', '')}</div>
                            <div style="margin: 8px 0; color: #333;">{rec.get('description', '')}</div>
                            <div style="font-size: 0.9em; color: #666;"><strong>Remediation:</strong> {rec.get('remediation', '')}</div>
                        </div>
                        '''
        
        # Detailed Security Headers Analysis
        section += '<h3>🔒 Security Headers Analysis</h3>'
        section += '<table><tr><th>Header</th><th>Status</th><th>Risk Level</th></tr>'
        
        for header, data in security.get('security_headers', {}).items():
            status = data.get('status', 'Unknown')
            risk_level = data.get('risk_level', 'LOW') 
            value = data.get('value', 'Not Set')
            
            risk_class = {
                'HIGH': 'status-404',
                'MEDIUM': 'status-other',
                'LOW': 'status-200'
            }.get(risk_level, 'status-200')
            
            if status == 'Present':
                section += f'<tr><td><strong>{header}</strong></td><td class="status-200">{value}</td><td class="{risk_class}">{risk_level}</td></tr>'
            else:
                section += f'<tr><td><strong>{header}</strong></td><td class="{risk_class}">{status}</td><td class="{risk_class}">{risk_level}</td></tr>'
        section += '</table>'
        
        return section
    
    def _generate_pages_section(self):
        section = '<table><tr><th>URL</th><th>Status</th><th>Title</th><th>Forms</th><th>Links</th></tr>'
        
        for page in self.results['pages']:
            status = page.get('status_code', 'Error')
            if status == 200:
                status_class = 'status-200'
            elif status == 404:
                status_class = 'status-404'
            else:
                status_class = 'status-other'
            
            title = page.get('title', 'N/A')[:50] + ('...' if len(page.get('title', '')) > 50 else '')
            forms_count = len(page.get('forms', []))
            links_count = len(page.get('links', []))
            
            section += f'''
            <tr>
                <td><a href="{page['url']}" target="_blank">{page['url'][:60]}...</a></td>
                <td class="{status_class}">{status}</td>
                <td>{title}</td>
                <td>{forms_count}</td>
                <td>{links_count}</td>
            </tr>
            '''
        
        section += '</table>'
        return section
    
    def _generate_forms_section(self):
        if not self.results['forms']:
            return '<div class="info-box">No forms found</div>'
        
        section = '<table><tr><th>Action</th><th>Method</th><th>Inputs</th></tr>'
        
        for form in self.results['forms']:
            inputs_text = ', '.join([f"{inp['name']} ({inp['type']})" for inp in form['inputs'] if inp['name']])
            section += f'<tr><td>{form["action"] or "Current page"}</td><td>{form["method"]}</td><td>{inputs_text}</td></tr>'
        
        section += '</table>'
        return section
    
    def _generate_headers_section(self):
        section = '<table><tr><th>Header</th><th>Value</th></tr>'
        
        for header, value in self.results['headers'].items():
            section += f'<tr><td><strong>{header}</strong></td><td>{value}</td></tr>'
        
        section += '</table>'
        return section


def main():
    parser = argparse.ArgumentParser(description='Passive Web Scanner')
    parser.add_argument('url', help='Target URL to scan')
    # Removed default output filename, will generate if not provided
    parser.add_argument('-o', '--output', help='Output HTML file (e.g., my_report.html). If not provided, a timestamped filename will be used.')
    parser.add_argument('-p', '--pages', type=int, default=10, help='Maximum pages to scan')
    # Changed default delay to a range
    parser.add_argument('-d', '--delay-range', type=float, nargs=2, default=[1, 5], 
                        help='Min and max delay between requests in seconds (e.g., 1 5)')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    # Generate a unique timestamped filename if output is not provided
    output_filename = args.output
    if not output_filename:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        # Prepend domain name to the filename for better organization
        domain_for_filename = urllib.parse.urlparse(args.url).netloc.replace('.', '_')
        output_filename = f"{domain_for_filename}_scan_report_{timestamp}.html"

    try:
        # Pass the delay range to the scanner
        scanner = WebScanner(args.url, max_pages=args.pages, delay_range=tuple(args.delay_range))
        results = scanner.scan()
        scanner.generate_html_report(output_filename) # Use the generated or provided filename
        
        print(f"\n✅ Scan completed successfully!")
        print(f"📄 Report saved to: {output_filename}")
        print(f"🔍 Scanned {len(results['pages'])} pages")
        print(f"⚙️ Detected {len(results['technologies'])} technologies")
        print(f"📝 Found {len(results['forms'])} forms")
        
    except KeyboardInterrupt:
        print("\n⏹️ Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error during scan: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
