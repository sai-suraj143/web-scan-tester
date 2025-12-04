import csv

csv_files = [
    "sql_injection_results.csv",
    "xss_results.csv",
    "auth_session_results.csv",
    "access_control_results.csv"
]

def combine_csvs(input_files, output_file):
    header = ["Type", "Endpoint", "Parameter", "Severity", "Details", "Mitigation"]
    all_rows = []
    for filename in input_files:
        try:
            with open(filename, "r") as f:
                reader = csv.reader(f)
                next(reader)  # skip header
                all_rows.extend(list(reader))
        except FileNotFoundError:
            print(f"[!] Warning: {filename} not found. Skipping.")
    with open(output_file, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for row in all_rows:
            writer.writerow(row)
    print(f"[*] Final report saved to {output_file}")

if __name__ == "__main__":
    combine_csvs(csv_files, "scan_results.csv")
