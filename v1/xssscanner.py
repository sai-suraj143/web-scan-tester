import json
import requests
import csv
from urllib.parse import urljoin

XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]

def check_xss(response, payload):
    return payload in response.text

def test_xss(form, session):
    url = form["url"]
    action_url = urljoin(url, form["action"])
    method = form["method"]
    rows = []
    print(f"\n[+] Testing {url} for XSS...")
    for payload in XSS_PAYLOADS:
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
            if check_xss(resp, payload):
                print(f"VULNERABLE: {action_url} with {field['name']} payload: {payload}")
                rows.append(["XSS", url, field["name"], "High", f"Payload {payload} reflected.", "Apply output encoding."])
        except Exception as e:
            print(f"[!] Error testing XSS on {action_url}: {e}")
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
        all_rows.extend(test_xss(form, session))
    save_results_to_csv("xss_results.csv", all_rows)
