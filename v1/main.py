import subprocess

def run_script(script_name):
    print(f"\n[+] Running {script_name} ...")
    result = subprocess.run(["python", script_name])
    if result.returncode != 0:
        print(f"[!] {script_name} failed.\n")
    else:
        print(f"[+] {script_name} completed.\n")

if __name__ == "__main__":
    run_script("crawler.py")
    run_script("sqlinjection.py")
    run_script("xssscanner.py")
    run_script("authentication_session_test.py")
    run_script("accesControl.py")
    run_script("security_test.py")