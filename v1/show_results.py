import csv
from datetime import datetime

def generate_html_report(csv_file, html_file, target_url="http://localhost", test_count=2, remediation_list=None):
    with open(csv_file, 'r', newline='') as f:
        reader = csv.reader(f)
        header = next(reader)
        findings = list(reader)

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    if remediation_list is None:
        remediation_list = [
            "Use parameterized queries/output encoding to prevent SQL injections.",
            "Sanitize user input, and escape output values to block XSS.",
            "Enforce strong password policies and secure session cookie flags.",
            "Perform server-side authorization checks, never trust user input for IDOR.",
            "Set HTTP security headers (e.g., Secure/HttpOnly for session cookies)."
        ]

    html = f"""
    <html>
    <head>
        <title>WebScanPro Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 30px; }}
            h1 {{ color: #1a73e8; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: center; }}
            th {{ background-color: #2196f3; color: white; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            .severity-High {{ color: white; background: #e53935; padding: 3px 6px; border-radius: 4px; }}
            .severity-Medium {{ color: white; background: #ffb300; padding: 3px 6px; border-radius: 4px; }}
            .severity-Low {{ color: white; background: #43a047; padding: 3px 6px; border-radius: 4px; }}
            .section-title {{ margin-top: 40px; margin-bottom: 10px; font-size: 1.2em; color: #333; }}
        </style>
    </head>
    <body>
        <h1>WebScanPro Report</h1>
        <b>Target:</b> {target_url} <br>
        <b>Date:</b> {now} <br>
        <div class='section-title'>Summary</div>
        <ul>
            <li>Test findings: {len(findings)}</li>
        </ul>
        <div class='section-title'>Findings</div>
        <table>
            <tr>
                {''.join(f'<th>{col}</th>' for col in header)}
            </tr>
    """

    # corrected row rendering
    for row in findings:
        row_html = ""
        for idx, cell in enumerate(row):
            col_name = header[idx].lower()
            if col_name == "severity":
                row_html += f'<td class="severity-{cell}">{cell}</td>'
            else:
                row_html += f'<td>{cell}</td>'
        html += f"<tr>{row_html}</tr>"

    html += """
        </table>
        <div class='section-title'>Suggested Remediations (high-level)</div>
        <ul>
    """
    for rec in remediation_list:
        html += f"<li>{rec}</li>"

    html += """
        </ul>
    </body>
    </html>
    """

    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[*] HTML report generated: {html_file}")

if __name__ == "__main__":
    generate_html_report("scan_results.csv", "WebScanPro_Report.html")
