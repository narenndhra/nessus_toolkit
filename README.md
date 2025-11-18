# Nessus Toolkit

This repository contains three Python utilities designed to simplify, clean, and visualize Nessus vulnerability scan outputs. Each script focuses on automating different parts of Nessus report handling.

---

## 📁 Tool 1 — `1.nessus_style_screenshot.py`

### **Purpose**
Generates **Nessus‑style vulnerability summary screenshots** from CSV exports.  
Organizes vulnerabilities **per‑IP**, creates an HTML summary, and converts it to a PNG image using `wkhtmltoimage`.

### **Key Features**
- Automatically parses Nessus CSV reports.
- Groups findings by severity (`Critical`, `High`, `Medium`, `Low`, `Info`).
- Creates a clean HTML visualization for each IP.
- Converts HTML into PNG using `wkhtmltoimage`.
- Shows progress using `tqdm`.
- Stores output under:  
  `nessus_screenshots/<csv_filename>/<ip>.png`

### **Usage**
```bash
python3 1.nessus_style_screenshot.py
```
Enter the folder path containing Nessus CSV files when prompted.

---

## 📁 Tool 2 — `info_issue_remove_from_nessus_reports.py`

### **Purpose**
Cleans Nessus CSV reports by removing **Informational** vulnerabilities.

### **Key Features**
- Reads all `.csv` files in the target folder.
- Removes rows where **Risk = Informational**.
- Keeps only: `Critical, High, Medium, Low`.
- Auto‑saves cleaned CSVs as `<filename>_cleaned.csv`.
- Uses multiprocessing for significant performance boost.
- Shows progress using `tqdm`.

### **Usage**
```bash
python3 info_issue_remove_from_nessus_reports.py
```

Modify the folder path inside the script if needed.

---

## 📁 Tool 3 — `3.plugin_output.py`

### **Purpose**
Creates **screenshots for each plugin output**, either:
- grouped **IP‑wise** (default Nessus style), or  
- grouped **Vulnerability‑wise**.

### **Key Features**
- Reads multiple CSV files in bulk.
- Generates formatted HTML/CSS output for each plugin output.
- Converts each plugin output into a PNG screenshot using `imgkit`.
- Supports multiprocessing for large‑scale processing.
- Two output modes:
  1. **IP-wise folders**
  2. **Vulnerability-wise folders**

### **Usage**
```bash
python3 3.plugin_output.py
```
Choose mode `1` or `2` when prompted.

---

## 📦 Requirements

Install dependencies:
```bash
pip install pandas tqdm imgkit
sudo apt install wkhtmltopdf  # required for wkhtmltoimage
```

For `imgkit` support on Linux:
```bash
sudo apt install wkhtmltopdf
```

---

## 📂 Folder Structure Example

```
nessus_toolkit/
│
├── 1.nessus_style_screenshot.py
├── info_issue_remove_from_nessus_reports.py
├── 3.plugin_output.py
└── README.md
```

---
## 👤 Author

**Narendra Reddy (Entersoft Security)**  
