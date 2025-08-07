
import os
import pandas as pd
import textwrap
import subprocess
import time
from multiprocessing import Pool
from tqdm import tqdm
import concurrent.futures

def menu():
    print("\nChoose an option:")
    print("1. Generate Nessus Vulnerability Screenshots (with summary)")
    print("2. Clean Nessus CSVs (Remove Info Risk Level)")
    print("3. Generate Screenshots from Plugin Output")
    return input("Enter choice (1/2/3): ").strip()

# ------------------------------------------
# Option 1: Generate Nessus HTML screenshots
# ------------------------------------------
def parse_nessus_csv(csv_file):
    df = pd.read_csv(csv_file)
    ips_vulns = {}
    for _, row in df.iterrows():
        ip = row['Host'].strip()
        severity = row['Risk'].strip().lower() if pd.notna(row['Risk']) else 'info'
        title = row['Name'].strip()
        os_info = row.get('Operating System', 'Unknown').strip()
        if ip not in ips_vulns:
            ips_vulns[ip] = {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': [], 'os_info': os_info}
        if severity in ips_vulns[ip]:
            ips_vulns[ip][severity].append(title)
    return ips_vulns

def create_html_summary(ip, vulnerabilities, scan_start_time, scan_end_time):
    color_map = {
        'critical': '#c9302c', 'high': '#d9534f',
        'medium': '#f0ad4e', 'low': '#5bc0de', 'info': '#5bc0de'
    }
    severity_counts = {sev: len(vulns) for sev, vulns in vulnerabilities.items() if sev != 'os_info'}
    os_info = vulnerabilities['os_info']
    html = f"""<html><head><style>body {{font-family: Arial;}}</style></head><body>
    <h2>Report for {ip}</h2><p>OS: {os_info}</p><p>Scan Time: {scan_start_time} to {scan_end_time}</p>
    <table border='1'><tr>{" ".join(f"<th>{sev.title()}</th>" for sev in severity_counts)}</tr>
    <tr>{" ".join(f"<td>{count}</td>" for count in severity_counts.values())}</tr></table>"""
    for sev, vulns in vulnerabilities.items():
        if sev != 'os_info' and vulns:
            html += f"<h3>{sev.title()}</h3><ul>" + "".join(f"<li>{v}</li>" for v in vulns[:5]) + "</ul>"
    return html + "</body></html>"

def capture_html_screenshot(html, out):
    subprocess.run(['wkhtmltoimage', '--disable-smart-width', html, out])

def process_nessus_ip(ip, vulns, folder, start, end):
    html_file = os.path.join(folder, f"{ip}.html")
    png_file = os.path.join(folder, f"{ip}.png")
    with open(html_file, "w") as f:
        f.write(create_html_summary(ip, vulns, start, end))
    capture_html_screenshot(html_file, png_file)
    os.remove(html_file)
    return ip

def run_nessus_screenshot():
    folder = input("Enter folder containing Nessus CSVs: ").strip()
    start, end = "Thu Aug 8 10:03:41 2024", "Thu Aug 8 10:12:15 2024"
    for file in os.listdir(folder):
        if file.endswith(".csv"):
            path = os.path.join(folder, file)
            output = os.path.join("nessus_screenshots", os.path.splitext(file)[0])
            os.makedirs(output, exist_ok=True)
            ips = parse_nessus_csv(path)
            with tqdm(total=len(ips), desc=f"Processing {file}", ncols=100) as pbar:
                with concurrent.futures.ProcessPoolExecutor() as executor:
                    futures = {executor.submit(process_nessus_ip, ip, vulns, output, start, end): ip for ip, vulns in ips.items()}
                    for future in concurrent.futures.as_completed(futures):
                        pbar.update(1)

# ------------------------------------------
# Option 2: Remove 'Info' Issues from CSV
# ------------------------------------------
def clean_csv(file_path):
    try:
        df = pd.read_csv(file_path)
        valid = df[df['Risk'].isin(['Critical', 'High', 'Medium', 'Low'])]
        out_path = file_path.replace('.csv', '_cleaned.csv')
        valid.to_csv(out_path, index=False)
        return f"✅ {os.path.basename(out_path)} saved."
    except Exception as e:
        return f"❌ Error: {e}"

def run_info_removal():
    folder = input("Enter folder path to clean Nessus CSVs: ").strip()
    files = [os.path.join(folder, f) for f in os.listdir(folder) if f.endswith('.csv')]
    with Pool() as pool:
        results = list(tqdm(pool.imap(clean_csv, files), total=len(files)))
    print("\n".join(results))

# ------------------------------------------
# Option 3: Plugin Output Screenshot
# ------------------------------------------
def create_plugin_screenshot(ip, name, proto, port, output, outdir):
    ip_dir = os.path.join(outdir, ip)
    os.makedirs(ip_dir, exist_ok=True)
    fname = (name[:50] + "...").replace(" ", "_").replace("/", "_")
    wrapped = "<br>".join(textwrap.wrap(output, 95))
    html = f"""<html><body><h3>Plugin Output</h3><hr><p>{proto}/{port}</p>
    <div style='background:#eee;padding:10px;'>{wrapped}</div></body></html>"""
    out = os.path.join(ip_dir, f"{fname}.png")
    import imgkit
    imgkit.from_string(html, out, options={'no-images': '', 'disable-local-file-access': ''})

def plugin_worker(ip, df, outdir):
    for _, row in df.iterrows():
        create_plugin_screenshot(ip, row['Name'], row['Protocol'], row['Port'], row['Plugin Output'] or "", outdir)

def run_plugin_screenshot():
    folder = input("Enter folder path containing plugin output CSVs: ").strip()
    csv_files = [os.path.join(folder, f) for f in os.listdir(folder) if f.endswith('.csv')]
    outdir = "./screenshots"
    os.makedirs(outdir, exist_ok=True)

    for csv in csv_files:
        df = pd.read_csv(csv)
        ip_column = 'Host'
        plugin_output_column = 'Plugin Output'
        plugin_name_column = 'Name'
        protocol_column = 'Protocol'
        port_column = 'Port'

        ip_addresses = df[ip_column].unique()
        vulnerabilities = df[[ip_column, plugin_name_column, plugin_output_column, protocol_column, port_column]]

        ip_process_info = [(ip, vulnerabilities[vulnerabilities[ip_column] == ip], outdir) for ip in ip_addresses]

        with Pool(processes=3) as pool:
            pool.starmap(plugin_worker, ip_process_info)

    print("✅ Plugin Output Screenshots created for all CSVs.")

# ------------------------------------------
# Main Execution
# ------------------------------------------
if __name__ == "__main__":
    choice = menu()
    if choice == "1":
        run_nessus_screenshot()
    elif choice == "2":
        run_info_removal()
    elif choice == "3":
        run_plugin_screenshot()
    else:
        print("Invalid choice.")
