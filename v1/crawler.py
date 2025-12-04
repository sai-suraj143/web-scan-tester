import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json

class WebScanProV1:
    def __init__(self, base_url, login_url=None, credentials=None):
        self.base_url = base_url
        self.session = requests.Session()
        self.visited = set()
        self.forms = []
        self.login_url = login_url
        self.credentials = credentials

    def login(self):
        print("[*] Attempting login...")
        try:
            response = self.session.get(self.login_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            token_tag = soup.find('input', {'name': 'user_token'})
            token = token_tag['value'] if token_tag else ''
            data = {
                'username': self.credentials.get('username', 'admin'),
                'password': self.credentials.get('password', 'password'),
                'Login': 'Login',
                'user_token': token
            }
            login_response = self.session.post(self.login_url, data=data)
            if "Logout" in login_response.text:
                print("[+] Login successful.")
                return True
            else:
                print("[!] Login might have failed. Check credentials.")
                return False
        except Exception as e:
            print(f"[!] Login Error: {e}")
            return False

    def is_valid(self, url):
        parsed = urlparse(url)
        return bool(parsed.netloc) and parsed.netloc in urlparse(self.base_url).netloc

    def get_links(self, url):
        try:
            response = self.session.get(url, timeout=5, verify=False)
            soup = BeautifulSoup(response.text, "html.parser")
            links = set()
            for a in soup.find_all("a", href=True):
                abs_link = urljoin(url, a["href"])
                if self.is_valid(abs_link):
                    links.add(abs_link)
            return links
        except Exception as e:
            print(f"[!] Error fetching links from {url}: {e}")
            return set()

    def get_forms(self, url):
        try:
            response = self.session.get(url, timeout=5, verify=False)
            soup = BeautifulSoup(response.text, "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action")
                method = form.get("method", "get").lower()
                inputs = []
                for input_tag in form.find_all("input"):
                    inputs.append({
                        "name": input_tag.get("name"),
                        "type": input_tag.get("type", "text"),
                        "value": input_tag.get("value", "")
                    })
                self.forms.append({
                    "url": url,
                    "action": urljoin(url, action),
                    "method": method,
                    "inputs": inputs
                })
        except Exception as e:
            print(f"[!] Error extracting forms from {url}: {e}")

    def crawl(self, url=None, depth=2):
        if url is None:
            url = self.base_url
        if url in self.visited or depth == 0:
            return
        print(f"[+] Crawling: {url}")
        self.visited.add(url)
        self.get_forms(url)
        links = self.get_links(url)
        for link in links:
            self.crawl(link, depth - 1)

    def save_results(self, filename="v1_scan_results.json"):
        data = {
            "base_url": self.base_url,
            "visited_pages": list(self.visited),
            "forms": self.forms
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        print(f"[*] Results saved to {filename}")

if __name__ == "__main__":
    target_url = "http://localhost:8080/dvwa/"
    login_url = "http://localhost:8080/dvwa/login.php"
    credentials = {"username": "admin", "password": "password"}
    scanner = WebScanProV1(base_url=target_url, login_url=login_url, credentials=credentials)
    if scanner.login():
        scanner.crawl(depth=2)
        scanner.save_results("v1_scan_results.json")
