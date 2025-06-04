Passive Web Scanner
A Python-based passive web scanner designed for initial reconnaissance of web applications. It passively collects information about a target website's structure, technologies, security headers, forms, and more, generating a detailed HTML report. The scanner incorporates several stealth features to minimize detectability by the host.

✨ Features
Passive Information Gathering: Collects data without sending malicious or intrusive requests.
HTML Report Generation: Creates a self-contained, human-readable HTML report with a clear overview of findings.
Security Analysis:
Overall risk assessment with a percentage score and risk level (Critical, High, Medium, Low).
Breakdown of component scores (OWASP, Security Headers, Cookies, Forms, SSL/TLS, Information Disclosure).
OWASP Top 10 (2021) assessment with findings and risk levels per category.
Detailed security header analysis.
Cookie security analysis.
Basic form security analysis.
SSL/TLS certificate information and security assessment.
Information disclosure checks.
Prioritized security recommendations (Critical, High, Medium, Low).
Technology Detection: Identifies common web technologies, CMS, frameworks, and server types.
robots.txt & Sitemap Analysis: Fetches and parses robots.txt and extracts sitemap URLs.
Link & Form Extraction: Discovers internal links and forms on scanned pages.
Stealth Features:
User-Agent Rotation: Randomly selects from a pool of common browser User-Agents.
Randomized Request Delays: Introduces varying delays between requests to mimic human Browse.
Referer Header Mimicry: Sets the Referer header to simulate legitimate navigation.
Randomized Header Order: Shuffles the order of common HTTP headers.
Connection: keep-alive: Uses persistent connections like real browsers.
Respects robots.txt: Adheres to Disallow rules to avoid being flagged as a misbehaving bot.
Intelligent Retry Logic: Retries transient server errors (e.g., 429, 5xx) with exponential backoff, but reports hard blocks (e.g., 401, 403) as errors immediately.
📋 Prerequisites
Before you can use this script, ensure you have:

Python 3.x installed.
The following Python libraries:
requests
BeautifulSoup4 (bs4)
You can install these libraries using pip:

Bash

pip install requests beautifulsoup4
🚀 Installation
Clone the repository (if this script is part of a larger project):
Bash

git clone <repository_url>
cd <repository_directory>
Download the script directly (if it's a standalone file): Save the provided Python code as web_scanner.py (or any other .py filename).
💡 Usage
Run the script from your terminal. You must provide a target URL.

Bash

python web_scanner.py <target_url> [options]
Command-line Arguments
<target_url> (required): The full URL of the website you want to scan (e.g., https://example.com). If http:// or https:// is omitted, https:// will be assumed.

-o, --output <filename>:

Specify the name of the output HTML report file (e.g., my_report.html).
If not provided, a unique filename will be generated automatically based on the target domain and a timestamp (e.g., example_com_scan_report_20250604_233000.html).
-p, --pages <number>:

The maximum number of internal pages to crawl and scan.
Default: 10. Increase this for a deeper scan, but be mindful of detectability and server load.
-d, --delay-range <min_delay> <max_delay>:

Specify the minimum and maximum delay (in seconds) between HTTP requests.
Default: 2 7 (random delay between 2 and 7 seconds).
Higher delays improve stealth but increase scan time.
Examples
1. Basic Scan (Default settings, timestamped report):

Bash

python web_scanner.py https://www.google.com
2. Scan with a custom report filename:

Bash

python web_scanner.py https://www.github.com -o github_scan.html
3. Scan more pages with a longer delay:

Bash

python web_scanner.py http://www.example.org -p 50 -d 5 15
4. Scan without providing scheme (https:// assumed):

Bash

python web_scanner.py openai.com
📊 Output Report
After the scan completes, an HTML report will be generated in the same directory where you run the script. The report is a single HTML file that you can open in any web browser.

The report includes:

Scan Information: Target, domain, scan date, pages scanned.
Table of Contents: Quick navigation to different sections.
SSL/TLS Information: Details about the SSL certificate (if HTTPS is used).
Technologies Detected: List of identified web technologies.
Security Analysis:
An overall risk assessment with a risk level and score.
Component-specific scores for various security aspects.
Detailed OWASP Top 10 findings.
Prioritized security recommendations.
Analysis of HTTP Security Headers.
Pages Information: A table summarizing each scanned page's URL, status code, title, and counts of forms/links.
Forms Analysis: Details about forms found on the site.
HTTP Headers: Raw HTTP response headers from the initial request.
Robots.txt Content: The content of the robots.txt file (if found).
👻 Stealth Features Explained
This scanner is designed with several features to minimize its footprint and avoid easy detection:

Randomized User-Agents: Each request uses a randomly chosen User-Agent string from a pool of common web browsers, making it harder to fingerprint the scanner by a consistent client signature.
Variable Delays: Instead of fixed intervals, requests are sent with random delays within a specified range. This unpredictable timing makes the activity look more natural and less like an automated script.
Dynamic Referer: When navigating from one page to another, the Referer HTTP header is correctly set to the previously visited page, mimicking a user clicking links.
Header Order Randomization: The order of non-essential HTTP headers is shuffled for each request, adding another layer of variability to the request fingerprint.
Persistent Connections (Connection: keep-alive): Requests are configured to prefer keeping the TCP connection alive, a standard practice for web browsers, which can reduce the number of new connection handshakes and make the traffic appear more typical.
robots.txt Compliance: The scanner checks and respects robots.txt rules, avoiding disallowed paths. This is a crucial ethical and practical measure for good web citizenship and avoiding blacklists.
Smart Error Handling: It differentiates between temporary server issues (which it retries) and explicit blocking (like 401/403 errors), stopping further attempts on blocked resources to prevent escalating detection.
⚠️ Limitations
Passive Only: This is a passive scanner. It doesn't perform active vulnerability testing (e.g., SQL injection, XSS attacks), nor does it interact with forms or execute JavaScript.
No Proxy Rotation: The script doesn't include built-in proxy rotation or VPN integration. For advanced stealth against IP-based blocking, consider using the script behind a proxy chain or a VPN.
Limited Deep Scanning: The max_pages limit is intended to keep the scan passive and quick. For comprehensive site mapping or exhaustive link discovery, dedicated crawling tools are more suitable.
No CAPTCHA/Bot Detection Bypass: The scanner doesn't attempt to solve CAPTCHAs or bypass advanced bot detection mechanisms. Encountering such defenses will likely result in the scanner being blocked from proceeding on that specific page or site.
