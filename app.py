from flask import Flask, render_template, request, jsonify, send_file, Response
import requests
import json
import time
import subprocess
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import whois

app = Flask(__name__)

# Security Headers Enumeration
SECURITY_HEADERS = {
    "X-Frame-Options": {"vulnerability": "Clickjacking attack possible", "severity": "High", "cve": "CVE-2010-4804", "recommendation": "Set to DENY or SAMEORIGIN to protect against clickjacking."},
    "Content-Security-Policy": {"vulnerability": "Possible XSS attack", "severity": "Critical", "cve": "CVE-2021-45046", "recommendation": "Define a strict CSP to prevent malicious script execution."},
    "Strict-Transport-Security": {"vulnerability": "Susceptible to MITM attacks", "severity": "High", "cve": "CVE-2014-3566", "recommendation": "Enable HSTS to enforce secure connections."},
    "X-Content-Type-Options": {"vulnerability": "MIME-type sniffing attack possible", "severity": "Medium", "cve": "N/A", "recommendation": "Set to nosniff to prevent MIME-based attacks."},
    "Referrer-Policy": {"vulnerability": "Sensitive data leakage possible", "severity": "Low", "cve": "N/A", "recommendation": "Use strict-origin-when-cross-origin to control referrer information."},
    "Permissions-Policy": {"vulnerability": "Potential unauthorized browser feature access", "severity": "Medium", "cve": "N/A", "recommendation": "Restrict access to browser features based on security needs."},
    "X-XSS-Protection": {"vulnerability": "XSS attacks possible", "severity": "High", "cve": "CVE-2016-7211", "recommendation": "Enable XSS protection or use CSP for better security."},
    "Expect-CT": {"vulnerability": "Misissued certificates undetected", "severity": "Medium", "cve": "N/A", "recommendation": "Enable Certificate Transparency enforcement."},
    "Cache-Control": {"vulnerability": "Sensitive data might be cached", "severity": "Medium", "cve": "N/A", "recommendation": "Use no-store, no-cache, must-revalidate for secure data handling."},
    "Set-Cookie": {"vulnerability": "Session hijacking risk without HttpOnly & Secure flags", "severity": "High", "cve": "N/A", "recommendation": "Use Secure and HttpOnly flags to protect cookies."},
    "Cross-Origin-Resource-Policy": {"vulnerability": "Risk of data theft via unauthorized cross-origin requests", "severity": "High", "cve": "N/A", "recommendation": "Restrict resource sharing using this policy."},
    "Cross-Origin-Opener-Policy": {"vulnerability": "Risk of cross-origin attacks affecting security contexts", "severity": "Medium", "cve": "N/A", "recommendation": "Use same-origin to enhance security."},
    "Cross-Origin-Embedder-Policy": {"vulnerability": "Potential risk of unauthorized embedding of content", "severity": "Medium", "cve": "N/A", "recommendation": "Set to require-corp to restrict embedding risks."}
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.json.get("url")
    if not url.startswith("http"):
        url = "http://" + url
    
    def generate():
        scan_details = {
            "url": url,
            "missing_headers": {},
            "open_ports": [],
            "subdomains": [],
            "directories": [],
            "vulnerabilities": [],
            "whois": {},
            "dns_records": [],
            "scan_progress": []
        }
        
        try:
            # Validate URL
            response = requests.get(url, timeout=5)
            headers = response.headers
            
            # Check security headers
            for index, header in enumerate(SECURITY_HEADERS):
                time.sleep(0.5)  # Simulating deep scan delay
                progress = int(((index + 1) / len(SECURITY_HEADERS)) * 100)
                scan_details["scan_progress"].append({"header": header, "progress": progress})
                
                # Send progress update to the frontend
                yield f"data: {json.dumps({'progress': progress, 'header': header})}\n\n"
                
                if header not in headers:
                    scan_details["missing_headers"][header] = SECURITY_HEADERS[header]
            
            # Perform Nmap scan for open ports
            domain = url.split("//")[-1].split("/")[0]
            nmap_result = subprocess.check_output(['nmap', '-sV', '-O', '-p', '1-1000', domain], stderr=subprocess.STDOUT)
            scan_details["open_ports"] = nmap_result.decode().splitlines()

            # Subdomain Enumeration (using Sublist3r)
            try:
                subdomains = subprocess.check_output(['sublist3r', '-d', domain], stderr=subprocess.STDOUT)
                scan_details["subdomains"] = subdomains.decode().splitlines()
            except Exception as e:
                scan_details["subdomains"] = [f"Subdomain enumeration failed: {str(e)}"]

            # Directory Bruteforcing (using Gobuster)
            try:
                directories = subprocess.check_output(['gobuster', 'dir', '-u', url, '-w', 'common.txt'], stderr=subprocess.STDOUT)
                scan_details["directories"] = directories.decode().splitlines()
            except Exception as e:
                scan_details["directories"] = [f"Directory enumeration failed: {str(e)}"]

            # Vulnerability Scanning (using Nikto)
            try:
                nikto_result = subprocess.check_output(['nikto', '-h', url], stderr=subprocess.STDOUT)
                scan_details["vulnerabilities"] = nikto_result.decode().splitlines()
            except Exception as e:
                scan_details["vulnerabilities"] = [f"Vulnerability scan failed: {str(e)}"]

            # WHOIS Lookup
            try:
                whois_info = whois.whois(domain)
                scan_details["whois"] = {
                    "registrar": whois_info.registrar,
                    "creation_date": str(whois_info.creation_date),
                    "expiration_date": str(whois_info.expiration_date),
                    "name_servers": whois_info.name_servers
                }
            except Exception as e:
                scan_details["whois"] = {"error": f"WHOIS lookup failed: {str(e)}"}

            # DNS Enumeration (using dig)
            try:
                dns_records = subprocess.check_output(['dig', domain, 'ANY'], stderr=subprocess.STDOUT)
                scan_details["dns_records"] = dns_records.decode().splitlines()
            except Exception as e:
                scan_details["dns_records"] = [f"DNS enumeration failed: {str(e)}"]

            # Save scan results to JSON
            with open("scan_results.json", "w") as f:
                json.dump(scan_details, f, indent=4)
            
            # Send final result to the frontend
            yield f"data: {json.dumps(scan_details)}\n\n"
        except requests.exceptions.RequestException as e:
            yield f"data: {json.dumps({'error': f'Network error: {str(e)}'})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(generate(), mimetype='text/event-stream')

@app.route('/download_report')
def download_report():
    with open("scan_results.json") as f:
        scan_data = json.load(f)

    filename = "security_scan_report.pdf"
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 16)
    c.drawString(200, height - 50, "Security Scan Report")

    c.setFont("Helvetica", 12)
    c.drawString(50, height - 100, f"Scanned URL: {scan_data['url']}")
    c.drawString(50, height - 120, "--------------------------------------")

    y = height - 150
    for header, details in scan_data["missing_headers"].items():
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, f"Header: {header}")
        y -= 20
        c.setFont("Helvetica", 11)
        c.drawString(60, y, f"Impact: {details['vulnerability']}")
        y -= 15
        c.drawString(60, y, f"Severity: {details['severity']}")
        y -= 15
        c.drawString(60, y, f"Recommendation: {details['recommendation']}")
        y -= 25
        if y < 50:  # New page if not enough space
            c.showPage()
            y = height - 50

    # Add open ports to the report
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Open Ports:")
    y -= 20
    c.setFont("Helvetica", 11)
    for line in scan_data["open_ports"]:
        c.drawString(60, y, line)
        y -= 15
        if y < 50:  # New page if not enough space
            c.showPage()
            y = height - 50

    # Add subdomains to the report
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Subdomains:")
    y -= 20
    c.setFont("Helvetica", 11)
    for line in scan_data["subdomains"]:
        c.drawString(60, y, line)
        y -= 15
        if y < 50:  # New page if not enough space
            c.showPage()
            y = height - 50

    # Add directories to the report
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Directories:")
    y -= 20
    c.setFont("Helvetica", 11)
    for line in scan_data["directories"]:
        c.drawString(60, y, line)
        y -= 15
        if y < 50:  # New page if not enough space
            c.showPage()
            y = height - 50

    # Add vulnerabilities to the report
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Vulnerabilities:")
    y -= 20
    c.setFont("Helvetica", 11)
    for line in scan_data["vulnerabilities"]:
        c.drawString(60, y, line)
        y -= 15
        if y < 50:  # New page if not enough space
            c.showPage()
            y = height - 50

    # Add WHOIS information to the report
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "WHOIS Information:")
    y -= 20
    c.setFont("Helvetica", 11)
    for key, value in scan_data["whois"].items():
        c.drawString(60, y, f"{key}: {value}")
        y -= 15
        if y < 50:  # New page if not enough space
            c.showPage()
            y = height - 50

    # Add DNS records to the report
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "DNS Records:")
    y -= 20
    c.setFont("Helvetica", 11)
    for line in scan_data["dns_records"]:
        c.drawString(60, y, line)
        y -= 15
        if y < 50:  # New page if not enough space
            c.showPage()
            y = height - 50

    c.save()
    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
