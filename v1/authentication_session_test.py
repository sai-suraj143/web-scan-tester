import requests
import csv

login_url = "http://localhost:8080/dvwa/login.php"
usernames = ["admin", "user", "test", "guest"]
passwords = ["password", "123456", "guest", "test"]
results = []

def brute_force_login():
    print("\n[+] Brute-force Login Testing...")
    for user in usernames:
        for pwd in passwords:
            session = requests.Session()
            data = {"username": user, "password": pwd, "Login": "Login"}
            resp = session.post(login_url, data=data)
            if "Logout" in resp.text or resp.status_code == 200:
                print(f"[!] Login Successful: {user}/{pwd}")
                results.append(["Auth", login_url, "username/password", "High",
                                f"Weak credentials found: {user}/{pwd}", "Enforce strong credentials."])
            else:
                print(f"Login Failed: {user}/{pwd}")

def check_cookie_security():
    print("\n[+] Session/Cookie Security Testing...")
    session = requests.Session()
    session.post(login_url, data={"username": "admin", "password": "password", "Login": "Login"})
    for cookie in session.cookies:
        flags = []
        if not cookie.secure:
            flags.append("No Secure flag")
        if not 'HttpOnly' in cookie._rest.keys():
            flags.append("No HttpOnly flag")
        if flags:
            print(f"[!] Insecure Cookie: {cookie.name} - {','.join(flags)}")
            results.append(["Session", login_url, cookie.name, "Medium",
                            f"Insecure cookie properties: {','.join(flags)}", "Set Secure and HttpOnly flags."])

def save_results_to_csv(filename, rows):
    header = ["Type", "Endpoint", "Parameter", "Severity", "Details", "Mitigation"]
    with open(filename, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for row in rows:
            writer.writerow(row)
    print(f"[*] Results saved to {filename}")

if __name__ == "__main__":
    brute_force_login()
    check_cookie_security()
    save_results_to_csv("auth_session_results.csv", results)
