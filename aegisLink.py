#!/usr/bin/env python3
"""
=============================================================================
           AEGIS-LINK : Advanced URL & Domain Security Scanner
=============================================================================
Author: Eng. Omar Al-Amiri
License: MIT
Cross-platform: Windows & Linux compatible (Zero mandatory external dependencies)
=============================================================================
"""

import sys
import os
import re
import socket
import ssl
import time
import json
import argparse
from datetime import datetime
import urllib.request
import urllib.parse
import urllib.error

# Enable ANSI colors on Windows terminals
if sys.platform == "win32":
    os.system('')

# ANSI Colors & Formatting
class Style:
    RESET       = "\033[0m"
    BOLD        = "\033[1m"
    DIM         = "\033[2m"
    UNDERLINE   = "\033[4m"
    
    # Foreground colors
    BLACK       = "\033[30m"
    RED         = "\033[31m"
    GREEN       = "\033[32m"
    YELLOW      = "\033[33m"
    BLUE        = "\033[34m"
    MAGENTA     = "\033[35m"
    CYAN        = "\033[36m"
    WHITE       = "\033[37m"
    
    # Bright foreground
    BRIGHT_RED     = "\033[91m"
    BRIGHT_GREEN   = "\033[92m"
    BRIGHT_YELLOW  = "\033[93m"
    BRIGHT_BLUE    = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN    = "\033[96m"
    BRIGHT_WHITE   = "\033[97m"
    
    # Backgrounds
    BG_RED      = "\033[41m"
    BG_GREEN    = "\033[42m"
    BG_YELLOW   = "\033[43m"
    BG_BLUE     = "\033[44m"
    BG_MAGENTA  = "\033[45m"
    BG_CYAN     = "\033[46m"

BANNER = f"""{Style.BRIGHT_CYAN}
   █████╗ ███████╗ ██████╗ ██╗███████╗██╗     ██╗███╗   ██╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝██║     ██║████╗  ██║██║ ██╔╝
  ███████║█████╗  ██║  ███╗██║███████╗██║     ██║██╔██╗ ██║█████╔╝ 
  ██╔══██║██╔══╝  ██║   ██║██║╚════██║██║     ██║██║╚██╗██║██╔═██╗ 
  ██║  ██║███████╗╚██████╔╝██║███████║███████╗██║██║ ╚████║██║  ██╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝{Style.RESET}
  {Style.BOLD}{Style.BRIGHT_MAGENTA}🛡️  AegisLink v2.0 - Ultimate URL & Web Threat Intelligence Scanner{Style.RESET}
  {Style.DIM}Crafted for Cybersecurity Specialists & Incident Responders{Style.RESET}
  {Style.CYAN}{"═"*72}{Style.RESET}
"""

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 AegisLink/2.0"

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security", "update",
    "banking", "account", "recovery", "password", "credential", "wallet",
    "paypal", "appleid", "microsoft", "google-security", "crypto", "blockchain",
    "confirm", "suspended", "unlock", "support-service", "auth", "token"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".work", ".buzz", ".click", ".fit", ".gq", ".ml", ".cf",
    ".ga", ".tk", ".surf", ".rest", ".club", ".icu", ".cam"
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "rebrand.ly", "rb.gy", "shorturl.at"
]

DANGEROUS_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".apk", ".jar", ".hta", ".dll", ".sh"
]


class RedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        super().__init__()
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append({
            "from_url": req.full_url,
            "status_code": code,
            "to_url": newurl
        })
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class URLScanner:
    def __init__(self, target_url, timeout=8):
        if not re.match(r'^[a-zA-Z]+://', target_url):
            target_url = "https://" + target_url
        self.target_url = target_url
        self.parsed = urllib.parse.urlparse(target_url)
        self.hostname = self.parsed.hostname or ""
        self.port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.scheme = self.parsed.scheme
        self.timeout = timeout
        
        self.results = {
            "target": self.target_url,
            "scan_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "dns": {},
            "heuristics": {"flags": [], "risk_points": 0},
            "ssl": {},
            "http": {"redirects": []},
            "headers_security": {},
            "summary": {}
        }

    def scan_dns(self):
        """Perform DNS and IP resolution"""
        try:
            ip_list = socket.gethostbyname_ex(self.hostname)
            canonical = ip_list[0]
            ips = ip_list[2]
            
            # Reverse DNS lookup on first IP
            reverse_host = "Unknown"
            if ips:
                try:
                    reverse_host = socket.gethostbyaddr(ips[0])[0]
                except (socket.herror, socket.gaierror):
                    pass
            
            self.results["dns"] = {
                "hostname": self.hostname,
                "canonical_name": canonical,
                "ip_addresses": ips,
                "primary_ip": ips[0] if ips else "Unresolved",
                "reverse_dns": reverse_host,
                "is_private_ip": any(self._is_private_ip(ip) for ip in ips)
            }
        except socket.gaierror as e:
            self.results["dns"] = {
                "error": f"Failed to resolve domain: {str(e)}",
                "ip_addresses": [],
                "primary_ip": "Unresolved"
            }
            self.results["heuristics"]["flags"].append("Domain does not resolve in DNS")
            self.results["heuristics"]["risk_points"] += 35

    def _is_private_ip(self, ip):
        """Check if an IP address belongs to RFC 1918 / Loopback"""
        private_patterns = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^169\.254\.'
        ]
        return any(re.match(pattern, ip) for pattern in private_patterns)

    def scan_heuristics(self):
        """Analyze URL structure for malicious or phishing patterns"""
        flags = []
        score = 0
        
        # 1. IP address used as hostname
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', self.hostname):
            flags.append("Hostname is a direct IP address (frequent in phishing / C2)")
            score += 30

        # 2. Homograph / Punycode
        if "xn--" in self.hostname:
            flags.append("Punycode / IDN Homograph domain detected (potential spoofing)")
            score += 25

        # 3. Excessive subdomains
        subdomain_parts = self.hostname.split(".")
        if len(subdomain_parts) > 4:
            flags.append(f"Excessive subdomain depth ({len(subdomain_parts)} parts)")
            score += 15

        # 4. Suspicious keywords in URL
        url_lower = self.target_url.lower()
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
        if found_keywords:
            flags.append(f"Contains sensitive/phishing keywords: {', '.join(found_keywords[:4])}")
            score += 15

        # 5. Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if self.hostname.endswith(tld):
                flags.append(f"Uses high-abuse top-level domain ({tld})")
                score += 20
                break

        # 6. URL Shortening service
        for shortener in SHORTENER_DOMAINS:
            if shortener in self.hostname:
                flags.append(f"URL Shortener detected ({shortener}) - target is cloaked")
                score += 15
                break

        # 7. Dangerous file extension in path
        path_lower = self.parsed.path.lower()
        for ext in DANGEROUS_EXTENSIONS:
            if path_lower.endswith(ext):
                flags.append(f"Direct link to executable / script payload ({ext})")
                score += 40
                break

        # 8. '@' symbol in URL (credentials masking trick)
        if "@" in self.target_url:
            flags.append("URL contains '@' character (used in URL masking attacks)")
            score += 25

        # 9. Non-standard port
        if self.port not in [80, 443]:
            flags.append(f"Non-standard web port in use ({self.port})")
            score += 10

        self.results["heuristics"]["flags"] = flags
        self.results["heuristics"]["risk_points"] = score

    def scan_ssl(self):
        """Inspect SSL/TLS certificate details"""
        if self.scheme != "https":
            self.results["ssl"] = {"status": "HTTP Only (Unencrypted)", "secure": False}
            self.results["heuristics"]["flags"].append("Plaintext HTTP connection (No SSL/TLS encryption)")
            self.results["heuristics"]["risk_points"] += 20
            return

        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Expiry calculation
                    not_after_str = cert.get("notAfter", "")
                    expire_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z") if not_after_str else None
                    days_remaining = (expire_date - datetime.utcnow()).days if expire_date else None
                    
                    # Extract issuer details
                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    subject_dict = dict(x[0] for x in cert.get("subject", []))
                    
                    ssl_info = {
                        "secure": True,
                        "protocol": version,
                        "cipher": cipher[0] if cipher else "Unknown",
                        "issuer_org": issuer_dict.get("organizationName", "Unknown"),
                        "common_name": subject_dict.get("commonName", self.hostname),
                        "expires_on": str(expire_date),
                        "days_remaining": days_remaining,
                        "expired": days_remaining is not None and days_remaining <= 0
                    }
                    
                    if ssl_info["expired"]:
                        self.results["heuristics"]["flags"].append("SSL Certificate is EXPIRED")
                        self.results["heuristics"]["risk_points"] += 35
                    elif days_remaining is not None and days_remaining < 15:
                        self.results["heuristics"]["flags"].append(f"SSL Certificate expires in {days_remaining} days")
                        self.results["heuristics"]["risk_points"] += 10
                        
                    self.results["ssl"] = ssl_info
        except ssl.SSLCertVerificationError as e:
            self.results["ssl"] = {"secure": False, "error": f"Certificate Verification Failed: {e.reason}"}
            self.results["heuristics"]["flags"].append("Untrusted / Invalid SSL Certificate")
            self.results["heuristics"]["risk_points"] += 35
        except Exception as e:
            self.results["ssl"] = {"secure": False, "error": f"SSL Connection Error: {str(e)}"}

    def scan_http_and_headers(self):
        """Execute HTTP request, trace redirects and inspect security headers"""
        redirect_handler = RedirectHandler()
        opener = urllib.request.build_opener(redirect_handler)
        req = urllib.request.Request(self.target_url, headers={"User-Agent": USER_AGENT})

        start_time = time.time()
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                headers = dict(resp.headers)
                status_code = resp.status
                final_url = resp.geturl()
                
                self.results["http"] = {
                    "status_code": status_code,
                    "response_time_ms": elapsed_ms,
                    "final_url": final_url,
                    "redirect_count": len(redirect_handler.chain),
                    "redirects": redirect_handler.chain,
                    "server": headers.get("Server", "Hidden/Unknown"),
                    "content_type": headers.get("Content-Type", "Unknown"),
                    "content_length": headers.get("Content-Length", "Unknown")
                }
                
                if len(redirect_handler.chain) > 3:
                    self.results["heuristics"]["flags"].append(f"Abnormal redirect chain length ({len(redirect_handler.chain)} redirects)")
                    self.results["heuristics"]["risk_points"] += 15

                # Security headers check
                self._evaluate_security_headers(headers)

        except urllib.error.HTTPError as e:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            self.results["http"] = {
                "status_code": e.code,
                "error": str(e),
                "response_time_ms": elapsed_ms,
                "final_url": self.target_url,
                "redirects": redirect_handler.chain
            }
            if e.headers:
                self._evaluate_security_headers(dict(e.headers))
        except urllib.error.URLError as e:
            self.results["http"] = {
                "error": f"Network / Connection error: {e.reason}",
                "redirects": []
            }
        except Exception as e:
            self.results["http"] = {
                "error": f"Scan execution failed: {str(e)}",
                "redirects": []
            }

    def _evaluate_security_headers(self, headers):
        """Audit HTTP security headers and assign grade"""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        audit = {
            "Strict-Transport-Security": headers_lower.get("strict-transport-security"),
            "Content-Security-Policy": headers_lower.get("content-security-policy"),
            "X-Frame-Options": headers_lower.get("x-frame-options"),
            "X-Content-Type-Options": headers_lower.get("x-content-type-options"),
            "Referrer-Policy": headers_lower.get("referrer-policy"),
            "Permissions-Policy": headers_lower.get("permissions-policy")
        }
        
        present_count = sum(1 for v in audit.values() if v is not None)
        total_headers = len(audit)
        
        if present_count == total_headers:
            grade = "A+"
        elif present_count >= 5:
            grade = "A"
        elif present_count >= 3:
            grade = "B"
        elif present_count >= 2:
            grade = "C"
        else:
            grade = "F"
            
        self.results["headers_security"] = {
            "audit": {k: ("PRESENT" if v else "MISSING") for k, v in audit.items()},
            "grade": grade,
            "implemented_count": f"{present_count}/{total_headers}"
        }

    def compute_summary(self):
        """Aggregate total risk score and final verdict"""
        score = self.results["heuristics"]["risk_points"]
        
        # Adjust for security headers grade
        grade = self.results.get("headers_security", {}).get("grade", "F")
        if grade in ["D", "F"]:
            score += 10
        elif grade in ["A", "A+"]:
            score = max(0, score - 5)
            
        # Bound score between 0 and 100
        total_score = min(100, max(0, score))
        
        if total_score >= 70:
            verdict = "DANGEROUS / HIGH RISK"
            color_class = "DANGER"
        elif total_score >= 40:
            verdict = "SUSPICIOUS / CAUTION"
            color_class = "WARNING"
        elif total_score >= 20:
            verdict = "MODERATE / UNCERTAIN"
            color_class = "MODERATE"
        else:
            verdict = "SAFE / REPUTABLE"
            color_class = "SAFE"
            
        self.results["summary"] = {
            "risk_score": total_score,
            "verdict": verdict,
            "verdict_level": color_class,
            "flags_count": len(self.results["heuristics"]["flags"])
        }

    def run(self):
        """Execute full intelligence scanning pipeline"""
        self.scan_dns()
        self.scan_heuristics()
        self.scan_ssl()
        self.scan_http_and_headers()
        self.compute_summary()
        return self.results


# Formatting & CLI Output
def print_box_line(left, middle, right, width=72):
    return f"{left}{middle * (width - 2)}{right}"

def render_report(data):
    """Render a visually stunning cybersecurity terminal report"""
    w = 74
    c_line = Style.CYAN + "═" * w + Style.RESET
    sub_line = Style.DIM + "─" * w + Style.RESET

    print(BANNER)
    
    # Target Information Bar
    print(f"{Style.BOLD}{Style.BRIGHT_WHITE}  TARGET URL :{Style.RESET} {Style.BRIGHT_CYAN}{data['target']}{Style.RESET}")
    print(f"{Style.BOLD}{Style.BRIGHT_WHITE}  TIMESTAMP  :{Style.RESET} {Style.DIM}{data['scan_time']}{Style.RESET}")
    print(c_line)

    # 1. Verdict & Risk Gauge
    summary = data["summary"]
    risk = summary["risk_score"]
    verdict = summary["verdict"]
    
    if summary["verdict_level"] == "SAFE":
        v_color = Style.BRIGHT_GREEN
        tag = f"{Style.BG_GREEN}{Style.BRIGHT_WHITE}  SAFE  {Style.RESET}"
    elif summary["verdict_level"] == "MODERATE":
        v_color = Style.BRIGHT_YELLOW
        tag = f"{Style.BG_YELLOW}{Style.BLACK}  NOTICE  {Style.RESET}"
    elif summary["verdict_level"] == "WARNING":
        v_color = Style.YELLOW
        tag = f"{Style.BG_YELLOW}{Style.BLACK}  WARNING  {Style.RESET}"
    else:
        v_color = Style.BRIGHT_RED
        tag = f"{Style.BG_RED}{Style.BRIGHT_WHITE}  CRITICAL  {Style.RESET}"

    # Progress bar for risk
    filled = int(risk / 5)
    bar = f"{v_color}{'█' * filled}{Style.DIM}{'░' * (20 - filled)}{Style.RESET}"

    print(f"  {tag} {Style.BOLD}OVERALL VERDICT:{Style.RESET} {v_color}{Style.BOLD}{verdict}{Style.RESET}")
    print(f"  {Style.BOLD}THREAT INDEX  :{Style.RESET} [{bar}] {v_color}{risk}/100{Style.RESET}")
    print(sub_line)

    # 2. DNS & Network Intelligence
    dns = data.get("dns", {})
    print(f"\n  {Style.BOLD}{Style.BRIGHT_MAGENTA}🌐 [1] DNS & INFRASTRUCTURE INTELLIGENCE{Style.RESET}")
    if "error" in dns:
        print(f"    {Style.RED}✖ {dns['error']}{Style.RESET}")
    else:
        ips_str = ", ".join(dns.get("ip_addresses", [])) or "None"
        print(f"    {Style.CYAN}• Hostname     :{Style.RESET} {dns.get('hostname')}")
        print(f"    {Style.CYAN}• Primary IP   :{Style.RESET} {Style.BOLD}{dns.get('primary_ip')}{Style.RESET}")
        print(f"    {Style.CYAN}• All IPs      :{Style.RESET} {ips_str}")
        print(f"    {Style.CYAN}• Reverse DNS  :{Style.RESET} {dns.get('reverse_dns')}")
        private_tag = f"{Style.RED}YES (RFC 1918 Private){Style.RESET}" if dns.get('is_private_ip') else f"{Style.GREEN}NO (Public){Style.RESET}"
        print(f"    {Style.CYAN}• Private IP   :{Style.RESET} {private_tag}")

    # 3. SSL / TLS Security
    ssl_data = data.get("ssl", {})
    print(f"\n  {Style.BOLD}{Style.BRIGHT_MAGENTA}🔒 [2] SSL / TLS CRYPTOGRAPHIC AUDIT{Style.RESET}")
    if ssl_data.get("secure"):
        days = ssl_data.get("days_remaining", 0)
        days_color = Style.GREEN if days > 30 else (Style.YELLOW if days > 0 else Style.RED)
        print(f"    {Style.GREEN}✔ Protocol     :{Style.RESET} {ssl_data.get('protocol')} ({ssl_data.get('cipher')})")
        print(f"    {Style.GREEN}✔ Authority    :{Style.RESET} {ssl_data.get('issuer_org')}")
        print(f"    {Style.GREEN}✔ Expiration   :{Style.RESET} {ssl_data.get('expires_on')} ({days_color}{days} days remaining{Style.RESET})")
    elif "error" in ssl_data:
        print(f"    {Style.RED}✖ Error        :{Style.RESET} {ssl_data['error']}")
    else:
        print(f"    {Style.YELLOW}⚠ Connection   :{Style.RESET} {ssl_data.get('status', 'Unencrypted HTTP')}")

    # 4. HTTP & Redirection Chain
    http_data = data.get("http", {})
    print(f"\n  {Style.BOLD}{Style.BRIGHT_MAGENTA}⚡ [3] HTTP RESPONSE & REDIRECTIONS{Style.RESET}")
    if "error" in http_data and "status_code" not in http_data:
        print(f"    {Style.RED}✖ Error        :{Style.RESET} {http_data['error']}")
    else:
        code = http_data.get("status_code", "N/A")
        code_color = Style.GREEN if str(code).startswith("2") else (Style.YELLOW if str(code).startswith("3") else Style.RED)
        print(f"    {Style.CYAN}• Status Code  :{Style.RESET} {code_color}{Style.BOLD}{code}{Style.RESET}")
        print(f"    {Style.CYAN}• Latency      :{Style.RESET} {http_data.get('response_time_ms', 'N/A')} ms")
        print(f"    {Style.CYAN}• Web Server   :{Style.RESET} {http_data.get('server')}")
        print(f"    {Style.CYAN}• Content-Type :{Style.RESET} {http_data.get('content_type')}")
        
        chain = http_data.get("redirects", [])
        if chain:
            print(f"\n    {Style.BOLD}{Style.YELLOW}↪ Redirection Traced ({len(chain)} hops):{Style.RESET}")
            for idx, hop in enumerate(chain, 1):
                print(f"      {Style.DIM}[Hop {idx}]{Style.RESET} ({hop['status_code']}) {hop['from_url']} {Style.CYAN}➔{Style.RESET} {hop['to_url']}")

    # 5. Security Headers Audit
    headers = data.get("headers_security", {})
    if headers:
        print(f"\n  {Style.BOLD}{Style.BRIGHT_MAGENTA}🛡️  [4] HTTP SECURITY HEADERS AUDIT{Style.RESET}")
        g = headers.get("grade", "F")
        g_color = Style.GREEN if g in ["A+", "A"] else (Style.YELLOW if g in ["B", "C"] else Style.RED)
        print(f"    {Style.CYAN}• Grade        :{Style.RESET} {g_color}{Style.BOLD}{g}{Style.RESET} ({headers.get('implemented_count')} active)")
        for h_name, status in headers.get("audit", {}).items():
            st_color = Style.GREEN + "✔ PRESENT" if status == "PRESENT" else Style.RED + "✖ MISSING"
            print(f"      {Style.DIM}•{Style.RESET} {h_name:<28}: {st_color}{Style.RESET}")

    # 6. Heuristic Red Flags
    flags = data.get("heuristics", {}).get("flags", [])
    print(f"\n  {Style.BOLD}{Style.BRIGHT_MAGENTA}🚩 [5] SUSPICIOUS INDICATORS & THREAT FLAGS ({len(flags)}){Style.RESET}")
    if not flags:
        print(f"    {Style.GREEN}✔ Zero malicious or phishing indicators detected.{Style.RESET}")
    else:
        for f in flags:
            print(f"    {Style.RED}⚠ {f}{Style.RESET}")

    print("\n" + c_line)
    print(f"  {Style.DIM}Scan powered by AegisLink Engine. Always verify unknown payloads manually.{Style.RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description="AegisLink - Cyber Threat Intelligence URL & Domain Security Scanner"
    )
    parser.add_argument("url", nargs="?", help="Target URL or domain to scan (e.g., https://example.com)")
    parser.add_argument("-f", "--file", help="Path to text file containing list of URLs to batch scan")
    parser.add_argument("-o", "--json", help="Export scan results to specified JSON file")
    parser.add_argument("-t", "--timeout", type=int, default=8, help="Connection timeout in seconds (Default: 8)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet output (only output risk score & verdict)")

    args = parser.parse_args()

    if not args.url and not args.file:
        print(BANNER)
        parser.print_help()
        sys.exit(1)

    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        if not os.path.exists(args.file):
            print(f"{Style.RED}Error: File '{args.file}' not found.{Style.RESET}")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8") as f:
            for line in f:
                cleaned = line.strip()
                if cleaned and not cleaned.startswith("#"):
                    targets.append(cleaned)

    all_results = []
    for target in targets:
        scanner = URLScanner(target, timeout=args.timeout)
        result = scanner.run()
        all_results.append(result)

        if not args.quiet:
            render_report(result)
        else:
            s = result["summary"]
            print(f"[{s['verdict_level']}] {target} -> Score: {s['risk_score']}/100 | {s['verdict']}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(all_results if len(all_results) > 1 else all_results[0], f, indent=2, ensure_ascii=False)
        print(f"{Style.GREEN}✔ Results successfully exported to '{args.json}'{Style.RESET}")


if __name__ == "__main__":
    main()

