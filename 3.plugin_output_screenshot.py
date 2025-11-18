import os
import pandas as pd
import textwrap
import imgkit
from multiprocessing import Pool

# Function to create screenshots with HTML and CSS
def create_screenshot(ip, vuln_name, protocol, port, plugin_output, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    vuln_filename = vuln_name[:50] + '...' if len(vuln_name) > 50 else vuln_name
    vuln_filename = vuln_filename.replace(" ", "_").replace("/", "_")

    wrapped_output = "<br>".join(textwrap.wrap(plugin_output, width=95))
    html_content = f"""
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f0f0f0;
                padding: 20px;
                color: #000;
            }}
            h3 {{ color: #3c3c3c; }}
            .code-block {{
                background-color: #e6e6e6;
                padding: 15px;
                border: 1px solid #b4b4b4;
                font-family: Courier, monospace;
                white-space: pre-wrap;
            }}
        </style>
    </head>
    <body>
        <h3><b>Plugin Output</b></h3>
        <hr>
        <p><b>{protocol}/{port}</b></p>
        <div class="code-block">{wrapped_output}</div>
    </body>
    </html>
    """

    options = {'no-images': '', 'disable-local-file-access': ''}
    screenshot_path = os.path.join(output_dir, f'{ip}_{vuln_filename}.png')
    imgkit.from_string(html_content, screenshot_path, options=options)

# Process one CSV
def process_csv_file(csv_file_path, base_output_dir, mode):
    file_name = os.path.splitext(os.path.basename(csv_file_path))[0]
    output_dir = os.path.join(base_output_dir, file_name)
    os.makedirs(output_dir, exist_ok=True)

    try:
        df = pd.read_csv(csv_file_path)
    except Exception as e:
        print(f"Failed to read {csv_file_path}: {e}")
        return

    required_columns = {'Host', 'Name', 'Plugin Output', 'Protocol', 'Port'}
    if not required_columns.issubset(df.columns):
        print(f"Missing required columns in {csv_file_path}")
        return

    if mode == "1":  # IP-wise
        for ip in df['Host'].unique():
            subset = df[df['Host'] == ip]
            ip_dir = os.path.join(output_dir, ip)
            for _, row in subset.iterrows():
                plugin_output = row['Plugin Output'] if pd.notna(row['Plugin Output']) else ""
                create_screenshot(ip, row['Name'], row['Protocol'], row['Port'], plugin_output, ip_dir)

    elif mode == "2":  # Vulnerability-wise
        for vuln_name in df['Name'].unique():
            subset = df[df['Name'] == vuln_name]
            vuln_dir = os.path.join(output_dir, vuln_name[:80].replace("/", "_").replace(" ", "_"))
            for _, row in subset.iterrows():
                plugin_output = row['Plugin Output'] if pd.notna(row['Plugin Output']) else ""
                create_screenshot(row['Host'], vuln_name, row['Protocol'], row['Port'], plugin_output, vuln_dir)

# Main execution
def main():
    folder_path = input("Enter the folder path containing CSV files: ")
    print("\nSelect output organization mode:")
    print("1. IP-wise folders (default Nessus style)")
    print("2. Vulnerability-wise folders")
    mode = input("Enter your choice (1 or 2): ").strip()
    if mode not in ["1", "2"]:
        print("Invalid option. Defaulting to IP-wise (1).")
        mode = "1"

    base_output_dir = './screenshots'
    os.makedirs(base_output_dir, exist_ok=True)

    if not os.path.isdir(folder_path):
        print("Invalid folder path provided.")
        return

    csv_files = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if f.endswith('.csv')]
    if not csv_files:
        print("No CSV files found in the provided folder.")
        return

    args = [(csv_file, base_output_dir, mode) for csv_file in csv_files]

    with Pool(processes=3) as pool:
        pool.starmap(process_csv_file, args)

    print("✅ Screenshots generated successfully.")

if __name__ == "__main__":
    main()


