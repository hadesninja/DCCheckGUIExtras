# fetch_cve_details.py
import os
import xml.etree.ElementTree as ET
import requests
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt5.QtGui import QColor

class CVEDetailsRetriever(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("CVE Details Retriever")
        self.setGeometry(200, 200, 1000, 500)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        self.label = QLabel("Enter CVE IDs (comma separated):")
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("e.g., CVE-2021-34527, CVE-2021-34528")

        self.button = QPushButton("Retrieve CVE Details")
        self.button.clicked.connect(self.retrieve_cve_details)

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "CVE ID", "Description", "Published Date", "Last Modified Date",
            "Severity", "Vector", "Base Score"
        ])

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)

        layout.addWidget(self.label)
        layout.addWidget(self.input_field)
        layout.addWidget(self.button)
        layout.addWidget(self.table)

        self.setLayout(layout)

    def get_api_key_from_config(self):
        # Path to the configuration XML file
        config_path = 'configuration.xml'

        # Check if the config file exists
        if os.path.exists(config_path):
            # Parse the XML file
            tree = ET.parse(config_path)
            root = tree.getroot()

            # Look for the API key in the XML structure (assuming the tag is <api_key>)
            api_key_element = root.find('nvd_api_key')

            # Return the key if found, otherwise return None
            return api_key_element.text if api_key_element is not None else None
        return None

    def retrieve_cve_details(self):
        cve_ids = self.input_field.text().strip().split(',')
        self.table.setRowCount(0)

        if not cve_ids or (len(cve_ids) == 1 and cve_ids[0] == ""):
            self.display_message("Please enter at least one CVE ID.")
            return

        # Get the API key from configuration
        api_key = self.get_api_key_from_config()

        for cve_id in map(str.strip, cve_ids):
            # Build the URL for the API request
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

            # Add the API key to the request if available
            headers = {}
            if api_key:
                headers['Authorization'] = f'Bearer {api_key}'
                print(f"Using API Key: {api_key}")  # Debugging statement to verify API key
            else:
                print("No API Key provided.")

            try:
                # Make the GET request to the NVD API
                response = requests.get(url, headers=headers)
                response.raise_for_status()  # Raise an exception for HTTP errors

                # If the response status is 403, print the headers and body for debugging
                if response.status_code == 403:
                    print("403 Forbidden error response:")
                    print(f"Response Headers: {response.headers}")
                    print(f"Response Body: {response.text}")

                # Parse the response JSON
                data = response.json()

                # Display the CVE details
                self.display_cve_details(data)

            except requests.exceptions.RequestException as e:
                # Display an error message in case of any request issues (like 403 or network errors)
                self.display_message(f"Request failed: {e}")

            except ValueError as e:
                # Handle JSON parsing errors
                self.display_message(f"Error parsing the response: {e}")

    def format_date(self, date_string):
        return date_string.split('T')[0] if date_string else "N/A"

    def get_severity_color(self, severity):
        color_map = {
            'low': QColor(76, 175, 80),
            'medium': QColor(255, 193, 7),
            'high': QColor(253, 67, 0),
            'critical': QColor(185, 4, 4)
        }
        return color_map.get(severity.lower(), QColor(255, 255, 255))

    def display_cve_details(self, details):
        if 'vulnerabilities' not in details or not details['vulnerabilities']:
            self.display_message("No vulnerabilities found for the given CVE ID.")
            return

        for vuln in details['vulnerabilities']:
            cve = vuln['cve']
            cve_id = cve.get('id', 'N/A')
            description = cve['descriptions'][0]['value'] if cve.get('descriptions') else 'N/A'
            published = self.format_date(cve.get('published'))
            modified = self.format_date(cve.get('lastModified'))

            metrics = cve.get('metrics', {})
            cvss_data = (metrics.get('cvssMetricV31') or metrics.get('cvssMetricV30') or [{}])[0].get('cvssData', {})

            severity = cvss_data.get('baseSeverity', 'N/A')
            vector = cvss_data.get('vectorString', 'N/A')
            base_score = cvss_data.get('baseScore', 'N/A')

            row_pos = self.table.rowCount()
            self.table.insertRow(row_pos)
            data = [cve_id, description, published, modified, severity, vector, str(base_score)]

            for i, item in enumerate(data):
                table_item = QTableWidgetItem(item)
                if i == 4:
                    table_item.setBackground(self.get_severity_color(severity))
                self.table.setItem(row_pos, i, table_item)

    def display_message(self, message):
        row_pos = self.table.rowCount()
        self.table.setRowCount(row_pos + 1)
        msg_item = QTableWidgetItem(message)
        self.table.setItem(row_pos, 0, msg_item)
        self.table.setSpan(row_pos, 0, 1, 7)

# No more code to directly run the window here
# So it can be imported into another program cleanly
