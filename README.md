# Nessus Toolkit

This is a unified Python tool to process Nessus scan CSV files with three core capabilities:

1. **Generate Summary Screenshots** – Visual HTML screenshot reports for vulnerabilities grouped by IP.
2. **Remove Info Risk Entries** – Clean all `.csv` files by removing entries with "Info" risk severity.
3. **Generate Plugin Output Screenshots** – Create plugin-specific screenshots from vulnerability plugin output.

---

## 📦 Requirements

Install required Python modules:

```bash
pip install -r requirements.txt
```

Install additional system tools:

```bash
sudo apt install wkhtmltopdf
```

---

## ▶️ How to Use

Run the tool:

```bash
python3 nessus_toolkit.py
```

Then choose from the menu:

```
1. Generate Nessus Vulnerability Screenshots (with summary)
2. Clean Nessus CSVs (Remove Info Risk Level)
3. Generate Screenshots from Plugin Output
```

Each option will ask for a **folder path** containing `.csv` files.

---

## 📂 Folder Structure Example

```
reports/
├── scan1.csv
├── scan2.csv
└── plugin_output.csv
```

---

## 📁 Output Structure

### Option 1 (Summary Screenshots)
```
nessus_screenshots/
└── scan1/
    └── 192.168.1.1.png
```

### Option 2 (Cleaned CSVs)
```
reports/
├── scan1.csv
└── scan1_cleaned.csv
```

### Option 3 (Plugin Output Screenshots)
```
screenshots/
└── 192.168.1.1/
    ├── Weak_Cipher.png
    └── Open_Port.png
```

---

## ✍️ Author

- Developed by Narendra Reddy (Entersoft Security)
