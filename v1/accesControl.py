import json
import requests
import csv
from urllib.parse import urljoin

ID_FIELDS = {'id', 'user', 'userid', 'user_id', 'account', 'account_id', 'profile', 'file', 'order', 'order_id'}
test_values = [1, 2, 9999, 1001]

def is_idor_field(field_name):
    name = field_name.lower()
    return any(key in name for key in ID_FIELDS)

def test_idor(form, session):
    url = form["url"]
    method = form["method"]
    action_url = urljoin(url, form["action"])
    rows = []
    print(f"\n[+] Testing {url} for Access Control/IDOR...")
    for field in form["inputs"]:
        if field["name"] and is_idor_field(field["name"]):
            for test_value in test_values:
                data = {f["name"]: f["value"] for f in form["inputs"] if f["name"]}
                data[field["name"]] = str(test_value)
                try:
                    if method == "post":
                        resp = session.post(action_url, data=data)
                    else:
                        resp = session.get(action_url, params=data)
                    if resp.status_code == 200 and str(test_value) in resp.text:
                        print(f"[!] Potential IDOR: {action_url} param {field['name']}={test_value}")
                        rows.append(["IDOR", url, field["name"], "High",
                                     f"IDOR test value {test_value} found in response.",
                                     "Enforce server-side access checks."])
                except Exception as e:
                    print(f"[!] Error testing IDOR on {action_url}: {e}")
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
        all_rows.extend(test_idor(form, session))
    save_results_to_csv("access_control_results.csv", all_rows)
