import os
import shutil
import subprocess
import threading
import datetime
import requests
import zipfile
import xml.etree.ElementTree as ET
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import QProcess
from PyQt5.QtWidgets import QMessageBox, QAction, QMenu, QWidget, QVBoxLayout, QApplication
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QGridLayout, QLabel, QPushButton, QMessageBox


class DependencyCheckGUI(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Dependency Check GUI")
        layout = QtWidgets.QVBoxLayout()

        # Menu Bar - File Menu
        self.menu_bar = QtWidgets.QMenuBar(self)
        self.file_menu = self.menu_bar.addMenu("File")

        # Open Folder Actions
        open_dc_reports_action = QtWidgets.QAction("Open DC Reports", self)
        open_dc_reports_action.triggered.connect(self.open_dc_reports)
        self.file_menu.addAction(open_dc_reports_action)

        open_logs_action = QtWidgets.QAction("Open Logs", self)
        open_logs_action.triggered.connect(self.open_logs)
        self.file_menu.addAction(open_logs_action)

        open_sca_jar_templates_action = QtWidgets.QAction("Open SCA_Jar_Templates", self)
        open_sca_jar_templates_action.triggered.connect(self.open_sca_jar_templates)
        self.file_menu.addAction(open_sca_jar_templates_action)

        # Settings Menu
        self.settings_menu = self.file_menu.addMenu("Settings")
        self.set_api_key_action = QtWidgets.QAction("Set NVD API Key", self)
        self.set_api_key_action.triggered.connect(self.set_nvd_api_key)
        self.settings_menu.addAction(self.set_api_key_action)

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(QtWidgets.qApp.quit)
        self.file_menu.addAction(exit_action)

        # === TOOLS MENU ===
        tools_menu = self.menu_bar.addMenu("Tools")

        # Plugins submenu
        self.plugins_menu = QMenu("Plugins", self)
        tools_menu.addMenu(self.plugins_menu)

        # Load Plugins action
        load_plugins_action = QAction("Load Plugins", self)
        load_plugins_action.triggered.connect(self.show_plugin_loader)
        tools_menu.addAction(load_plugins_action)

        # Populate plugins
        self.populate_plugins_menu()

        # Menu Bar - Help Menu
        self.help_menu = self.menu_bar.addMenu("Help")
        self.download_dc_action = QtWidgets.QAction("Update DC Tools", self)
        self.download_dc_action.triggered.connect(self.download_dependency_check)
        self.help_menu.addAction(self.download_dc_action)

        self.check_dc_version = QtWidgets.QAction("Check DC Tools Version", self)
        self.check_dc_version.triggered.connect(self.check_dctools_version)
        self.help_menu.addAction(self.check_dc_version)

        self.about_action = QAction("About", self)
        self.about_action.triggered.connect(self.show_about_dialog)
        self.help_menu.addAction(self.about_action)

        layout.setMenuBar(self.menu_bar)

        # Folder selection
        folder_layout = QtWidgets.QHBoxLayout()
        self.folder_label = QtWidgets.QLabel("Select folder to scan:")
        folder_layout.addWidget(self.folder_label)
        self.folder_entry = QtWidgets.QLineEdit()
        folder_layout.addWidget(self.folder_entry)
        self.folder_button = QtWidgets.QPushButton("Select")
        self.folder_button.clicked.connect(self.browse_source_path)
        folder_layout.addWidget(self.folder_button)
        layout.addLayout(folder_layout)

        # File selection
        file_layout = QtWidgets.QHBoxLayout()
        self.file_label = QtWidgets.QLabel("Select files to scan:")
        file_layout.addWidget(self.file_label)
        self.file_entry = QtWidgets.QLineEdit()
        file_layout.addWidget(self.file_entry)
        self.file_button = QtWidgets.QPushButton("Select")
        self.file_button.clicked.connect(self.browse_files)
        file_layout.addWidget(self.file_button)
        layout.addLayout(file_layout)

        # Project Name
        project_layout = QtWidgets.QHBoxLayout()
        self.project_label = QtWidgets.QLabel("Project Name:")
        project_layout.addWidget(self.project_label)
        self.project_entry = QtWidgets.QLineEdit()
        project_layout.addWidget(self.project_entry)
        layout.addLayout(project_layout)

        # Report format dropdown
        format_layout = QtWidgets.QHBoxLayout()
        self.format_label = QtWidgets.QLabel("Report Format:")
        format_layout.addWidget(self.format_label)
        self.format_dropdown = QtWidgets.QComboBox()
        self.format_dropdown.addItems(["HTML", "CSV", "XML"])
        format_layout.addWidget(self.format_dropdown)
        layout.addLayout(format_layout)

        # Start scan button
        self.scan_button = QtWidgets.QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)

        # Output text
        self.output_text = QtWidgets.QTextEdit()
        self.output_text.setReadOnly(True)
        layout.addWidget(self.output_text)

        self.setLayout(layout)
        self.ensure_folders()

    def open_folder(self, folder_name):
        """Open the folder in the system's default file explorer."""
        folder_path = os.path.join(os.getcwd(), folder_name)
        if os.path.exists(folder_path):
            if os.name == 'nt':  # For Windows
                subprocess.run(['explorer', folder_path])
            elif os.name == 'posix':  # For Linux/MacOS
                subprocess.run(['xdg-open', folder_path])
        else:
            QtWidgets.QMessageBox.warning(self, "Folder Not Found", f"{folder_name} folder does not exist.")

    def open_dc_reports(self):
        self.open_folder("Reports")

    def open_logs(self):
        self.open_folder("Logs")

    def open_sca_jar_templates(self):
        self.open_folder("SCA_Jar_Templates")

    def show_about_dialog(self):
        QtWidgets.QMessageBox.about(
            self,
            "About Dependency Check GUI",
            (
                "<h3>Dependency Check GUI</h3>"
                "<p><b>Version:</b> 1.7</p>"
                "<p>A lightweight GUI interface for managing OWASP Dependency Check scans.</p>"
                "<p>This tool provides a user-friendly interface for Windows users to download and run OWASP Dependency Check command-line tools and generate reports.</p>"
                "<p>It simplifies the use of Dependency Check by abstracting the complexity of the command-line.</p>"
                "<p><b>Developed by:</b> Vaibhav Patil</p>"
            )
        )

    #Define a method show_plugin_loader that opens a dialog displaying the plugins:
    def show_plugin_loader(self):
        try:
            # Fetch plugin list
            response = requests.get(
                "https://raw.githubusercontent.com/hadesninja/DCCheckGUIExtras/master/plugins/pluginlist.txt")
            response.raise_for_status()
            plugin_lines = response.text.strip().splitlines()
        except requests.RequestException as e:
            QMessageBox.critical(self, "Error", f"Failed to fetch plugin list:\n{e}")
            return

        # Parse plugin entries
        plugins = []
        for line in plugin_lines:
            if ':' in line:
                exe_name, description = map(str.strip, line.split(':', 1))
                plugins.append((exe_name, description))

        # Load configuration.xml
        config_path = os.path.join(os.getcwd(), "configuration.xml")
        installed_plugins = set()
        if os.path.exists(config_path):
            tree = ET.parse(config_path)
            root = tree.getroot()
            plugin_list = root.find("PluginList")
            if plugin_list is not None:
                for plugin in plugin_list.findall("Plugin"):
                    installed_plugins.add(plugin.get("file"))

        # Create dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Load Plugins")
        layout = QVBoxLayout(dialog)

        # Create grid layout for plugins
        grid = QGridLayout()
        layout.addLayout(grid)

        # Ensure plugins directory exists
        plugins_dir = os.path.join(os.getcwd(), "plugins")
        os.makedirs(plugins_dir, exist_ok=True)

        # Populate grid with plugins
        for row, (exe_name, description) in enumerate(plugins):
            # Plugin description
            label = QLabel(description)
            grid.addWidget(label, row, 0)

            # Status label
            status = QLabel()
            if exe_name in installed_plugins:
                status.setText("Installed")
                status.setStyleSheet("color: green; font-weight: bold;")
            else:
                status.setText("Not Installed")
                status.setStyleSheet("color: orange; font-weight: bold;")
            grid.addWidget(status, row, 1)

            # Action button
            if exe_name in installed_plugins:
                action_button = QPushButton("Uninstall")
                action_button.clicked.connect(lambda _, exe=exe_name: self.uninstall_plugin(exe, plugins_dir))
            else:
                action_button = QPushButton("Install")
                action_button.clicked.connect(
                    lambda _, exe=exe_name, desc=description: self.download_plugin(exe, desc, plugins_dir))
            grid.addWidget(action_button, row, 2)

        dialog.exec_()

    #uninstall_plugin method to handle plugin removal
    def uninstall_plugin(self, exe_name, plugins_dir):
        # Delete the plugin executable
        exe_path = os.path.join(plugins_dir, exe_name)
        if os.path.exists(exe_path):
            try:
                os.remove(exe_path)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete {exe_name}:\n{e}")
                return

        # Update configuration.xml
        config_path = os.path.join(os.getcwd(), "configuration.xml")
        if os.path.exists(config_path):
            tree = ET.parse(config_path)
            root = tree.getroot()
            plugin_list = root.find("PluginList")
            if plugin_list is not None:
                for plugin in plugin_list.findall("Plugin"):
                    if plugin.get("file") == exe_name:
                        plugin_list.remove(plugin)
                        break
                tree.write(config_path, encoding='utf-8', xml_declaration=True)

        QMessageBox.information(self, "Uninstalled", f"{exe_name} has been uninstalled successfully.")

        # Prompt to restart the application
        reply = QMessageBox.question(
            self,
            "Restart Required",
            "Plugin uninstalled successfully. Restart the application to update the Plugins menu?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            QApplication.quit()

    #During application startup, read configuration.xml and populate the "Plugins" submenu:
    def populate_plugins_menu(self):
        config_path = os.path.join(os.getcwd(), "configuration.xml")
        if not os.path.exists(config_path):
            return

        tree = ET.parse(config_path)
        root = tree.getroot()
        plugin_list = root.find("PluginList")
        if plugin_list is None:
            return

        for plugin in plugin_list.findall("Plugin"):
            exe_name = plugin.get("file")
            description = plugin.get("name")
            if exe_name and description:
                action = QAction(description, self)
                action.triggered.connect(lambda _, exe=exe_name: self.launch_plugin(exe))
                self.plugins_menu.addAction(action)

    #Define the method to launch the selected plugin:
    def launch_plugin(self, exe_name):
        plugins_dir = os.path.join(os.getcwd(), "plugins")
        exe_path = os.path.join(plugins_dir, exe_name)

        if not os.path.exists(exe_path):
            QMessageBox.critical(self, "Error", f"Plugin executable not found: {exe_path}")
            return

        process = QProcess(self)
        process.setWorkingDirectory(plugins_dir)
        process.start(exe_path)

        if not process.waitForStarted():
            QMessageBox.critical(self, "Error", f"Failed to launch plugin: {exe_name}")

    #Define the download_plugin method to handle downloading the plugin executable:
    def download_plugin(self, exe_name, description, plugins_dir):
        url = f"https://raw.githubusercontent.com/hadesninja/DCCheckGUIExtras/master/plugins/{exe_name}"
        local_path = os.path.join(plugins_dir, exe_name)

        try:
            response = requests.get(url, stream=True)
            response.raise_for_status()

            with open(local_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

            # Update configuration.xml
            config_path = os.path.join(os.getcwd(), "configuration.xml")
            if not os.path.exists(config_path):
                # Create a new configuration file if it doesn't exist
                root = ET.Element("configuration")
                tree = ET.ElementTree(root)
                tree.write(config_path, encoding='utf-8', xml_declaration=True)

            tree = ET.parse(config_path)
            root = tree.getroot()

            # Find or create PluginList element
            plugin_list = root.find("PluginList")
            if plugin_list is None:
                plugin_list = ET.SubElement(root, "PluginList")

            # Check if plugin already exists
            exists = any(plugin.get("file") == exe_name for plugin in plugin_list.findall("Plugin"))

            if not exists:
                plugin = ET.SubElement(plugin_list, "Plugin")
                plugin.set("file", exe_name)
                plugin.set("name", description)
                tree.write(config_path, encoding='utf-8', xml_declaration=True)

            QMessageBox.information(self, "Success", f"{exe_name} has been downloaded and registered successfully.")

            # Prompt to restart the application
            reply = QMessageBox.question(
                self,
                "Restart Required",
                "Plugin installed successfully. Restart the application to load new plugins?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                QApplication.quit()

        except requests.RequestException as e:
            QMessageBox.critical(self, "Download Error", f"Failed to download {exe_name}:\n{e}")

    def fetch_cve_details(self):
        self.sca_utility_window = QProcess()
        self.sca_utility_window.start("python", ["fetch_cve_details.py"])
        if not self.sca_utility_window.waitForStarted():
            print("Failed to launch the SCA Template Utility.")

    def check_dctools_version(parent: QWidget):
        # Path to dependency-check.bat
        dep_check_path = os.path.join("dependency-check", "bin", "dependency-check.bat")

        # If dependency-check.bat doesn't exist
        if not os.path.exists(dep_check_path):
            reply = QMessageBox.question(
                parent,
                "Dependency Check Not Found",
                "The 'dependency-check.bat' file could not be found.\nYou can download the latest version of Dependency-Check.\n\nDo you want to download it?",
                QMessageBox.Ok | QMessageBox.Cancel
            )

            if reply == QMessageBox.Ok:
                parent.download_dependency_check()  # ✅ Call the method from the main window
            return

        # Execute the version check
        command = f'"{dep_check_path}" --version'
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                QMessageBox.information(parent, "Dependency Check Version", stdout.strip())
            else:
                QMessageBox.critical(parent, "Error", stderr.strip())
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(parent, "Error", str(e))


    def ensure_folders(self):
        for folder in ("Reports", "Logs", "SCA_Jar_Templates", "Backups", "dependency-check"):
            os.makedirs(folder, exist_ok=True)

    def browse_source_path(self):
        folder = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if folder:
            self.folder_entry.setText(folder)
            self.file_entry.clear()  # Clear file entry when folder is selected

    def browse_files(self):
        files, _ = QtWidgets.QFileDialog.getOpenFileNames(self, "Select Files to Scan", "",
                                                          "Supported files (*.jar *.js *.lock *.h *.nuspec *.csproj *.vbproj *.zip *.ear *.war *.sar *.apk *.nupkg *.exe *.dll);;All files (*.*)")
        if files:
            self.file_entry.setText(",".join(files))  # Use comma instead of semicolon
            self.folder_entry.clear()  # Clear folder entry when files are selected

    def append_output(self, text):
        self.output_text.append(text)

    def clean_dependency_check_folder(self, extract_path):
        if os.path.exists(extract_path):
            for item in os.listdir(extract_path):
                item_path = os.path.join(extract_path, item)
                if item != "data":  # Preserve the 'data' folder
                    if os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                    else:
                        os.remove(item_path)

    def set_nvd_api_key(self):
        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle("Set NVD API Key")

        layout = QtWidgets.QVBoxLayout(dialog)

        label = QtWidgets.QLabel("Enter NVD API Key:")
        layout.addWidget(label)

        api_key_entry = QtWidgets.QLineEdit()
        layout.addWidget(api_key_entry)

        button_layout = QtWidgets.QHBoxLayout()
        save_button = QtWidgets.QPushButton("Save")
        cancel_button = QtWidgets.QPushButton("Cancel")

        save_button.clicked.connect(lambda: self.save_nvd_api_key(api_key_entry.text(), dialog))
        cancel_button.clicked.connect(dialog.reject)

        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)

        dialog.exec_()

    def save_nvd_api_key(self, key, dialog):
        if not key.strip():
            QMessageBox.warning(self, "Invalid Input", "API key cannot be empty.")
            return

        try:
            program_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(program_dir, "configuration.xml")

            if os.path.exists(config_path):
                tree = ET.parse(config_path)
                root = tree.getroot()

                # Check if <nvd_api_key> already exists
                api_key_element = root.find('nvd_api_key')
                if api_key_element is None:
                    api_key_element = ET.SubElement(root, "nvd_api_key")
                    api_key_element.text = key.strip()
                    tree.write(config_path, encoding="utf-8", xml_declaration=True)
                    QMessageBox.information(self, "Success", f"NVD API Key added to:\n{config_path}")
                else:
                    QMessageBox.information(self, "Info", "NVD API Key already exists in configuration.")
            else:
                # Create a new configuration.xml
                root = ET.Element("configuration")
                api_key_element = ET.SubElement(root, "nvd_api_key")
                api_key_element.text = key.strip()

                tree = ET.ElementTree(root)
                tree.write(config_path, encoding="utf-8", xml_declaration=True)
                QMessageBox.information(self, "Success", f"NVD API Key saved to:\n{config_path}")

            dialog.accept()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save configuration:\n{e}")

    def download_dependency_check(self):
        """Download and extract the latest Dependency Check version correctly with a progress bar."""
        version_url = "https://dependency-check.github.io/DependencyCheck/current.txt"

        try:
            self.append_output("Fetching latest Dependency Check version...")
            version_response = requests.get(version_url)
            if version_response.status_code == 200:
                version = version_response.text.strip()
                download_url = f"https://github.com/dependency-check/DependencyCheck/releases/download/v{version}/dependency-check-{version}-release.zip"
                save_path = "dependency-check.zip"
                extract_temp = "dependency-check-temp"
                extract_final = "dependency-check"

                self.append_output("Cleaning up existing Dependency Check folder...")
                self.clean_dependency_check_folder(extract_final)

                self.append_output(f"Downloading Dependency Check {version}...")

                # Create progress bar
                progress_dialog = QtWidgets.QProgressDialog("Downloading Dependency Check...", "Cancel", 0, 100, self)
                progress_dialog.setWindowTitle("Downloading")
                progress_dialog.setWindowModality(QtCore.Qt.WindowModal)
                progress_dialog.setMinimumDuration(0)
                progress_dialog.setAutoClose(True)
                progress_dialog.setAutoReset(True)

                response = requests.get(download_url, stream=True)
                if response.status_code == 200:
                    total_size = int(response.headers.get("content-length", 1))
                    downloaded_size = 0

                    with open(save_path, "wb") as file:
                        for chunk in response.iter_content(chunk_size=1024):
                            if chunk:
                                file.write(chunk)
                                downloaded_size += len(chunk)

                                # Update progress bar
                                percent = int((downloaded_size / total_size) * 100)
                                progress_dialog.setValue(percent)
                                if progress_dialog.wasCanceled():
                                    self.append_output("Download canceled.")
                                    os.remove(save_path)
                                    return

                    self.append_output("Download complete. Extracting files...")
                    with zipfile.ZipFile(save_path, "r") as zip_ref:
                        zip_ref.extractall(extract_temp)
                    os.remove(save_path)

                    # Move extracted files correctly
                    extracted_main_folder = os.path.join(extract_temp, "dependency-check")
                    if os.path.exists(extracted_main_folder):
                        for item in os.listdir(extracted_main_folder):
                            shutil.move(os.path.join(extracted_main_folder, item), extract_final)
                        shutil.rmtree(extract_temp)  # Clean up temp folder

                    self.append_output("Dependency Check is ready to use.")
                else:
                    self.append_output("Failed to download Dependency Check.")
            else:
                self.append_output("Failed to fetch the latest version.")
        except Exception as e:
            self.append_output(f"Error: {str(e)}")

    def start_scan(self):
        source_path = self.folder_entry.text().strip()
        files = self.file_entry.text().strip().split(",")  # Split by comma
        project_name = self.project_entry.text().strip()
        report_format = self.format_dropdown.currentText().upper()
        dep_check_path = os.path.abspath(os.path.join("dependency-check", "bin", "dependency-check.bat"))

        if not project_name or (not source_path and not any(files)):
            QtWidgets.QMessageBox.warning(self, "Invalid Input", "Please enter a valid project name and scan path.")
            return

        if not os.path.exists(dep_check_path):
            reply = QtWidgets.QMessageBox.question(
                self, "Error", "Dependency Check not found. Download now?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.Yes)
            if reply == QtWidgets.QMessageBox.Yes:
                self.download_dependency_check()
            return

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"{project_name}_{timestamp}.{report_format.lower()}"
        output_file_path = os.path.abspath(os.path.join("Reports", report_filename))
        log_file_path = os.path.abspath(os.path.join("Logs", f"{project_name}_{timestamp}.log"))

        scan_paths = [os.path.abspath(source_path)] if source_path else []
        scan_paths += [os.path.abspath(file) for file in files if file]

        command = [
            dep_check_path, "--project", project_name,
            "--scan", *scan_paths,
            "--out", output_file_path, "--format", report_format
        ]

        # Load API key if available
        config_path = os.path.abspath("configuration.xml")
        api_key = None
        if os.path.exists(config_path):
            try:
                tree = ET.parse(config_path)
                root = tree.getroot()
                api_key = root.findtext("nvd_api_key")
            except ET.ParseError:
                self.append_output("Error parsing configuration.xml")

        if not api_key:
            self.set_nvd_api_key()
            if os.path.exists(config_path):
                try:
                    tree = ET.parse(config_path)
                    root = tree.getroot()
                    api_key = root.findtext("nvd_api_key")
                except ET.ParseError:
                    self.append_output("Error parsing configuration.xml after setting key")

        if api_key:
            command += ["--nvdApiKey", api_key]

        def run_scan():
            self.append_output(f"Running: {' '.join(command)}")
            try:
                with open(log_file_path, "w", encoding="utf-8") as log_file:
                    log_file.write(f"Command: {' '.join(command)}\n\n")
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                               shell=True)
                    for line in iter(process.stdout.readline, ''):
                        if line:
                            cleaned_line = line.strip()
                            QtCore.QMetaObject.invokeMethod(
                                self.output_text, "append", QtCore.Qt.QueuedConnection,
                                QtCore.Q_ARG(str, cleaned_line)
                            )
                            log_file.write(cleaned_line + "\n")
                    process.wait()
            except Exception as e:
                error_msg = f"Error: {str(e)}"
                QtCore.QMetaObject.invokeMethod(
                    self.output_text, "append", QtCore.Qt.QueuedConnection,
                    QtCore.Q_ARG(str, error_msg)
                )
                with open(log_file_path, "a", encoding="utf-8") as log_file:
                    log_file.write(error_msg + "\n")
            finally:
                QtCore.QMetaObject.invokeMethod(
                    self, "scan_finished", QtCore.Qt.QueuedConnection,
                    QtCore.Q_ARG(str, output_file_path)
                )

        self.scan_button.setEnabled(False)
        threading.Thread(target=run_scan, daemon=True).start()

    @QtCore.pyqtSlot(str)
    def scan_finished(self, output_file_path):
        self.scan_button.setEnabled(True)
        QtWidgets.QMessageBox.information(
            self, "Scan Complete",
            f"Scan completed successfully.\nReport saved at:\n{output_file_path}"
        )

if __name__ == "__main__":
    app = QtWidgets.QApplication([])
    gui = DependencyCheckGUI()
    gui.show()
    app.exec_()