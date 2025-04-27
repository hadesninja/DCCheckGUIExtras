# sca_template_utility.py

import os
import sys
import json
import hashlib
import pandas as pd
import datetime
import urllib.parse
from urllib.request import urlopen
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QFileDialog, QTextEdit, QHBoxLayout, QMessageBox,
    QProgressBar, QTabWidget, QFormLayout
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt

# Severity mapping
severity_order = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1
}

# --- SCAGUI (SCA Template Generator) ---
class ScanWorker(QThread):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal(str)

    def __init__(self, folder_path, report_name):
        super().__init__()
        self.folder_path = folder_path
        self.report_filename = report_name if report_name else datetime.datetime.now().strftime("sca_report_%Y%m%d_%H%M%S")

    def run(self):
        try:
            self.log("Starting scan...")
            jar_files = []
            for root, _, files in os.walk(self.folder_path):
                for name in files:
                    if name.endswith(".jar"):
                        jar_files.append((os.path.join(root, name), name))

            total = len(jar_files)
            if total == 0:
                self.log("No .jar files found.")
                self.finished_signal.emit("")
                return

            with open("sha1.txt", "w") as sha1file:
                for i, (full_path, name) in enumerate(jar_files):
                    sha1 = self.compute_sha1(full_path)
                    sha1file.write(f"{sha1} {name}\n")
                    self.log(f"Processed: {name}")
                    self.progress_signal.emit(int((i + 1) / total * 100))

            output_data = self.analyze_sha1_data()
            if output_data:
                os.makedirs("SCA_Jar_Templates", exist_ok=True)
                output_path = os.path.join("SCA_Jar_Templates", f"{self.report_filename}.xlsx")
                pd.DataFrame(output_data).to_excel(output_path, index=False)
                self.log(f"Template saved to: {output_path}")
                self.finished_signal.emit(output_path)
            else:
                self.log("No data to export.")
                self.finished_signal.emit("")

        except Exception as e:
            self.log(f"Error: {str(e)}")
            self.finished_signal.emit("")

    def log(self, message):
        self.log_signal.emit(message)

    def compute_sha1(self, filepath):
        with open(filepath, "rb") as f:
            return hashlib.sha1(f.read()).hexdigest()

    def analyze_sha1_data(self):
        output_data = []
        with open("sha1.txt", "r") as f:
            lines = f.readlines()

        for i, line in enumerate(lines):
            sha, jar = line.strip().split(" ", 1)
            try:
                search_url = f"http://search.maven.org/solrsearch/select?q=1:{sha}&rows=20&wt=json"
                response = urlopen(search_url)
                data = json.load(response)

                if data["response"]["numFound"] > 0:
                    doc = data["response"]["docs"][0]
                    latest = self.get_latest_version(doc)
                    output_data.append(self.build_output_entry(jar, doc, latest))
                    self.log(f"Found info for {jar}")
                else:
                    output_data.append(self.build_empty_output_entry(jar))
                    self.log(f"Info not found for {jar}")
            except Exception as e:
                self.log(f"Error retrieving {jar}: {e}")
            self.progress_signal.emit(int((i + 1) / len(lines) * 100))
        return output_data

    def get_latest_version(self, jarinfo):
        query = f'g:"{jarinfo["g"]}" AND a:"{jarinfo["a"]}"'
        url = f'https://search.maven.org/solrsearch/select?q={urllib.parse.quote(query)}&core=gav&rows=20&wt=json'
        try:
            response = urlopen(url)
            data = json.load(response)
            if data["response"]["numFound"] > 0:
                doc = data["response"]["docs"][0]
                return doc["v"], datetime.datetime.fromtimestamp(doc["timestamp"] / 1000.0).strftime("%Y-%m-%d")
        except:
            pass
        return "-", "-"

    def build_output_entry(self, jar, jarinfo, latest_version):
        return {
            "LIBRARY NAME": jar, "eCW LIBRARY/THIRDPARTY LIBRARY": "",
            "ARTIFACT ID": jarinfo["a"], "Group ID": jarinfo["g"],
            "IS VULNERABLE LIBRARY": "", "LIBRARY CURRENT VERSION": jarinfo["v"],
            "RELEASE DATE OF LIBRARY(CURRENT VERSION)": datetime.datetime.fromtimestamp(jarinfo["timestamp"] / 1000.0).strftime("%Y-%m-%d"),
            "RECENT MOST VERSION AVAILABLE": latest_version[0],
            "RELEASE DATE OF LIBRARY(RECENT MOST VERSION AVAILABLE)": latest_version[1],
            "LIBRARY STATUS": "", "IS VULNERABLE RECENT MOST VERSION AVAILABLE": "",
            "CVE CURRENT VERSION": "", "SEVERITY OF CVE": "", "VULNERABILITY REFERENCE": "",
            "IS ECW PRODUCT AFFECTED/NOT AFFECTED": "", "RISK TO ECW": "",
            "COMMENT FOR ECW RISK": "", "LAST UPGRADED DATE IN ECW APPLICATION": "",
            "JIRA ID": "", "JIRA STATUS": "", "COMMENTS": "", "Additional Comments": ""
        }

    def build_empty_output_entry(self, jar):
        return self.build_output_entry(jar, {"a": "-", "g": "-", "v": "-", "timestamp": 0}, ("-", "-"))

class SCAGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SCA Template Generator")
        self.setGeometry(300, 300, 650, 450)

        layout = QVBoxLayout()

        folder_layout = QHBoxLayout()
        self.folder_input = QLineEdit()
        folder_btn = QPushButton("Select Folder")
        folder_btn.clicked.connect(self.select_folder)
        folder_layout.addWidget(QLabel("Folder to Scan:"))
        folder_layout.addWidget(self.folder_input)
        folder_layout.addWidget(folder_btn)
        layout.addLayout(folder_layout)

        name_layout = QHBoxLayout()
        self.name_input = QLineEdit()
        name_layout.addWidget(QLabel("Template File Name:"))
        name_layout.addWidget(self.name_input)
        layout.addLayout(name_layout)

        self.generate_btn = QPushButton("Generate SCA Template")
        self.generate_btn.clicked.connect(self.start_scan)
        layout.addWidget(self.generate_btn)

        self.progress = QProgressBar()
        self.progress.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.progress)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output)

        self.setLayout(layout)

    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            self.folder_input.setText(folder)

    def start_scan(self):
        folder = self.folder_input.text().strip()
        name = self.name_input.text().strip()

        if not folder:
            QMessageBox.warning(self, "Missing Input", "Please select a folder to scan.")
            return

        self.generate_btn.setEnabled(False)
        self.progress.setValue(0)
        self.log_output.clear()

        self.worker = ScanWorker(folder, name)
        self.worker.log_signal.connect(self.log)
        self.worker.progress_signal.connect(self.progress.setValue)
        self.worker.finished_signal.connect(self.scan_complete)
        self.worker.start()

    def log(self, message):
        self.log_output.append(message)

    def scan_complete(self, filepath):
        self.generate_btn.setEnabled(True)
        self.progress.setValue(100)
        if filepath:
            QMessageBox.information(self, "Scan Complete", f"Template saved to:\n{filepath}")
        else:
            QMessageBox.warning(self, "No Output", "No template was generated.")

class SCAJarTemplateProcessor(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SCA Jar Template Processor")
        self.setGeometry(300, 200, 600, 400)

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        form_layout = QFormLayout()

        self.csv_entry = QLineEdit()
        csv_browse_btn = QPushButton("Select")
        csv_browse_btn.clicked.connect(self.browse_csv)
        csv_layout = QHBoxLayout()
        csv_layout.addWidget(self.csv_entry)
        csv_layout.addWidget(csv_browse_btn)
        form_layout.addRow("Jar DC Report (CSV):", csv_layout)

        self.excel_entry = QLineEdit()
        excel_browse_btn = QPushButton("Select")
        excel_browse_btn.clicked.connect(self.browse_excel)
        excel_layout = QHBoxLayout()
        excel_layout.addWidget(self.excel_entry)
        excel_layout.addWidget(excel_browse_btn)
        form_layout.addRow("SCA Jar Template (Excel):", excel_layout)

        layout.addLayout(form_layout)

        self.process_btn = QPushButton("Update SCA Jar Template")
        self.process_btn.clicked.connect(self.process_files)
        layout.addWidget(self.process_btn)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output)

        self.setLayout(layout)

    def log(self, message):
        self.log_output.append(message)
        self.log_output.verticalScrollBar().setValue(self.log_output.verticalScrollBar().maximum())

    def browse_csv(self):
        initial_dir = os.path.join(os.getcwd(), 'reports')
        file_path, _ = QFileDialog.getOpenFileName(self, "Select CSV File", initial_dir, "CSV Files (*.csv)")
        if file_path:
            self.csv_entry.setText(file_path)

    def browse_excel(self):
        initial_dir = os.path.join(os.getcwd(), 'SCA_Jar_Templates')
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Excel File", initial_dir, "Excel Files (*.xlsx)")
        if file_path:
            self.excel_entry.setText(file_path)

    def process_files(self):
        csv_file = self.csv_entry.text()
        excel_file = self.excel_entry.text()

        self.log_output.clear()

        if not csv_file or not excel_file:
            self.log("Error: Please select both CSV and Excel files!")
            return

        try:
            self.log(f"Loading CSV file: {csv_file}")
            csv_df = pd.read_csv(csv_file)

            self.log(f"Loading Excel file: {excel_file}")
            excel_df = pd.read_excel(excel_file)

            self.replace_date_with_hyphen(csv_df)
            self.replace_date_with_hyphen(excel_df)

            required_csv_columns = ['DependencyName', 'CVE', 'CVSSv3_BaseSeverity']
            required_excel_columns = ['LIBRARY NAME', 'CVE CURRENT VERSION', 'SEVERITY OF CVE']

            if not all(col in csv_df.columns for col in required_csv_columns):
                self.log("Error: CSV file missing required columns!")
                return

            if not all(col in excel_df.columns for col in required_excel_columns):
                self.log("Error: Excel file missing required columns!")
                return

            csv_df.columns = csv_df.columns.str.strip()
            excel_df.columns = excel_df.columns.str.strip()

            severity_dict = csv_df.groupby('DependencyName')['CVSSv3_BaseSeverity'].apply(list).to_dict()

            def get_highest_severity(cves):
                severities = [severity_order.get(sev, 0) for sev in cves]
                highest = max(severities) if severities else 0
                return next((k for k, v in severity_order.items() if v == highest), '-')

            def update_row(row):
                lib_name = row['LIBRARY NAME'].strip()
                if lib_name in severity_dict:
                    related_cves = csv_df[csv_df['DependencyName'] == lib_name]['CVE']
                    row['CVE CURRENT VERSION'] = ','.join(related_cves)
                    row['SEVERITY OF CVE'] = get_highest_severity(severity_dict[lib_name])
                    row['IS VULNERABLE LIBRARY'] = 'Yes'
                    self.log(f"Updated: {lib_name} (Vulnerable)")
                else:
                    for field in ['CVE CURRENT VERSION', 'SEVERITY OF CVE', 'VULNERABILITY REFERENCE',
                                  'IS ECW PRODUCT AFFECTED/NOT AFFECTED', 'RISK TO ECW', 'COMMENT FOR ECW RISK',
                                  'LAST UPGRADED DATE IN ECW APPLICATION', 'JIRA ID', 'JIRA STATUS', 'COMMENTS',
                                  'Additional Comments', 'IS VULNERABLE LIBRARY']:
                        row[field] = 'NA'
                    row['IS VULNERABLE LIBRARY'] = 'No'
                    self.log(f"No CVE info for: {lib_name}")

                if row.get('ARTIFACT ID', "").strip() not in ["", "-"]:
                    row['eCW LIBRARY/THIRDPARTY LIBRARY'] = 'Third Party'

                row['LIBRARY STATUS'] = self.get_library_status(row)
                return row

            excel_df = excel_df.apply(update_row, axis=1)
            excel_df.to_excel(excel_file, index=False)

            self.log(f"Success: CVE data updated successfully in: {excel_file}")
            # Add this popup after success
            QMessageBox.information(self, "Success", f"CVE data updated successfully!\n\nFile saved at:\n{excel_file}")

        except Exception as e:
            self.log(f"Error occurred: {str(e)}")

    def replace_date_with_hyphen(self, df):
        from datetime import datetime

        for col in df.columns:
            df[col] = df[col].apply(
                lambda x: "-" if (
                        isinstance(x, str) and
                        (
                            (lambda d: d and d.year < 1995)(
                                datetime.strptime(x, "%Y-%m-%d")
                                if all(part.isdigit() for part in x.split("-")) and len(x.split("-")) == 3
                                else None
                            )
                        )
                ) else x
            )

    def get_library_status(self, row):
        current_version_date = pd.to_datetime(row.get('RELEASE DATE OF LIBRARY(CURRENT VERSION)', ""), errors='coerce')
        latest_version_date = pd.to_datetime(row.get('RELEASE DATE OF LIBRARY(RECENT MOST VERSION AVAILABLE)', ""),
                                             errors='coerce')

        if pd.isna(current_version_date):
            return '#Error - No Version Date'

        now = datetime.datetime.now()
        current_years_diff = (now - current_version_date).days / 365.25
        latest_years_diff = (now - latest_version_date).days / 365.25 if pd.notna(latest_version_date) else float('inf')

        if current_years_diff > 5 and latest_years_diff > 5:
            return 'EOL'
        elif current_years_diff > 5:
            return 'Outdated'
        elif current_version_date != latest_version_date:
            return 'Update Available'
        return 'No Update Available'

def launch_sca_template_utility():
    app = QApplication(sys.argv)
    window = QWidget()
    layout = QVBoxLayout()

    tabs = QTabWidget()
    tabs.addTab(SCAGUI(), "SCA Template Generator")
    tabs.addTab(SCAJarTemplateProcessor(), "SCA Jar Template Processor")
    layout.addWidget(tabs)

    window.setLayout(layout)
    window.setWindowTitle("SCA Template Utility")
    window.setGeometry(300, 100, 700, 500)
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    launch_sca_template_utility()
