from tkinter.scrolledtext import ScrolledText
import subprocess
import requests
import zipfile
import shutil
import webbrowser
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import hashlib
import json
from datetime import datetime
import os
import pandas as pd
import urllib.parse
from urllib.request import urlopen
import datetime


# Ensure required folders exist
def ensure_folders():
    folders = ["reports", "logs"]
    for folder in folders:
        if not os.path.exists(folder):
            os.makedirs(folder)


# Function to browse source path
def browse_source_path():
    source_directory = filedialog.askdirectory(title="Select folder to scan")
    if source_directory:
        source_entry.delete(0, tk.END)
        source_entry.insert(0, source_directory)


# Function to browse files to scan
def browse_files():
    file_types = [
        ("Supported files",
         "*.jar *.js *.lock *.h *.nuspec *.csproj *.vbproj *.zip *.ear *.war *.sar *.apk *.nupkg *.exe *.dll"),
        ("All files", "*.*")
    ]
    files = filedialog.askopenfilenames(
        title="Select Files",
        filetypes=file_types
    )
    if files:
        files_entry.delete(0, tk.END)
        files_entry.insert(0, ";".join(files))


# Funtion to open the reports and logs folder in the file explorer
def open_folder(folder_name):
    # Get the current working directory
    current_directory = os.getcwd()
    # Create the full path for the folder
    folder_path = os.path.join(current_directory, folder_name)

    # Check if the folder exists
    if os.path.exists(folder_path):
        # Open the folder using the default file explorer
        if os.name == 'nt':  # For Windows
            subprocess.run(["explorer", folder_path])
        elif os.name == 'posix':  # For macOS/Linux
            subprocess.run(["open", folder_path])  # macOS
            # subprocess.run(["xdg-open", folder_path])  # Linux
    else:
        # Folder doesn't exist
        messagebox.showerror("Folder does not exist",
                             f"Folder '{folder_name}' does not exist in the current directory.")


# Function to clean the dependency-check folder
def clean_dependency_check_folder():
    dep_check_folder = os.path.join(os.getcwd(), "dependency-check")
    if os.path.exists(dep_check_folder):  # Proceed only if the folder exists
        for item in os.listdir(dep_check_folder):
            item_path = os.path.join(dep_check_folder, item)
            if os.path.isdir(item_path) and item == "data":
                continue  # Skip the data directory
            if os.path.isdir(item_path):
                shutil.rmtree(item_path)  # Remove folder
            elif os.path.isfile(item_path):
                os.remove(item_path)  # Remove file


# Function to check Dependency Check version
def check_version():
    # Construct the path for dependency-check.bat
    dep_check_path = os.path.join("dependency-check", "bin", "dependency-check.bat")

    # Check if the path exists
    if not os.path.exists(dep_check_path):
        # Show the message box with an option to download Dependency-Check
        response = messagebox.askokcancel(
            "Dependency Check Not Found",
            "The 'dependency-check.bat' file could not be found. You can download the latest version of Dependency-Check.\n\nClick OK to download."
        )

        if response:  # If user clicked "OK"
            download_dependency_check()  # Trigger the download
        return  # Exit the function if the path is invalid

    command = f'"{dep_check_path}" --version'
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            messagebox.showinfo("Dependency Check Version", stdout.strip())
        else:
            messagebox.showerror("Error", stderr.strip())
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", e.stderr.decode())


# Function to purge NVD data and check if Dependency Check exist if not download it
def purge_NVD_data():
    # Construct the path for dependency-check.bat
    dep_check_path = os.path.join("dependency-check", "bin", "dependency-check.bat")

    # Check if the file exists
    if not os.path.exists(dep_check_path):
        # Show message box to inform the user about missing dependency-check.bat and offer to download
        response = messagebox.askokcancel(
            "Dependency Check Not Found",
            "The 'dependency-check.bat' file could not be found. You can download the latest version of Dependency-Check.\n\nClick OK to download."
        )

        if response:  # If the user clicked "OK"
            download_dependency_check()  # Trigger the download
        return  # Exit the function if the path is invalid

    # Construct the command to purge NVD data
    command = f'"{dep_check_path}" --purge'

    try:
        # Execute the purge command using subprocess
        print("Purging NVD data...")
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)

        # If the output contains the specific message about missing the database, show a user-friendly message
        if "Unable to purge database; the database file does not exist" in result.stderr:
            messagebox.showinfo("No Data to Purge", "No NVD data found to purge.")
        elif result.returncode == 0:
            # If purge was successful
            messagebox.showinfo("Purge Successful", "NVD data has been successfully purged.")
        else:
            # If the command fails for any other reason, show an error message
            messagebox.showerror("Purge Failed", f"Failed to purge NVD data: {result.stderr}")

    except subprocess.CalledProcessError as e:
        # Handle any error in executing the command
        if "Unable to purge database; the database file does not exist" in e.stderr:
            messagebox.showinfo("No Data to Purge", "No NVD data found to purge.")
        else:
            messagebox.showinfo("No Data to Purge", "No NVD data found to purge.")


# Function to download the latest version of Dependency Check
def download_dependency_check():
    download_popup = tk.Toplevel(root)
    download_popup.title("Downloading Dependency Check")
    download_progress = tk.DoubleVar()
    progress_bar = ttk.Progressbar(download_popup, variable=download_progress, maximum=100, length=300)
    progress_bar.grid(row=0, column=0, padx=10, pady=10)

    def download_task():
        try:
            version_response = requests.get("https://jeremylong.github.io/DependencyCheck/current.txt", timeout=10)
            version_response.raise_for_status()
            version = version_response.text.strip()
            download_url = f"https://github.com/jeremylong/DependencyCheck/releases/download/v{version}/dependency-check-{version}-release.zip"
            response = requests.get(download_url, stream=True)
            total_size = int(response.headers.get('content-length', 0))

            if total_size == 0:
                messagebox.showerror("Download Error", "Failed to retrieve the file.")
                download_popup.destroy()
                return

            zip_file_path = "dependency-check.zip"
            with open(zip_file_path, "wb") as file:
                downloaded_size = 0
                for data in response.iter_content(chunk_size=1024):
                    file.write(data)
                    downloaded_size += len(data)
                    download_progress.set((downloaded_size / total_size) * 100)
                    download_popup.update_idletasks()

                    # Clean the dependency-check folder, preserving the data directory
                    clean_dependency_check_folder()

            # Extract the zip file
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                zip_ref.extractall(".")

            # Delete the zip file after extraction
            if os.path.exists(zip_file_path):
                os.remove(zip_file_path)

            messagebox.showinfo("Download Complete",
                                f"Downloaded and extracted the latest version of Dependency Check to the current directory.")
            download_popup.destroy()
        except requests.RequestException as e:
            messagebox.showerror("Download Error", f"An error occurred while downloading: {e}")
            download_popup.destroy()

    threading.Thread(target=download_task).start()


# Function to open the version selection window
def open_version_selection_window():
    try:
        response = requests.get("https://api.github.com/repos/jeremylong/DependencyCheck/releases", timeout=10)
        response.raise_for_status()
        releases = response.json()
        versions = [release["tag_name"].lstrip("v") for release in releases]

        if not versions:
            messagebox.showinfo("No Versions Found", "No available versions were found.")
            return

        # Create the new window
        version_window = tk.Toplevel(root)
        version_window.title("Select Dependency Check Version")
        tk.Label(version_window, text="Select a version to download:").grid(row=0, column=0, padx=10, pady=10)

        # Dropdown menu for versions
        selected_version = tk.StringVar(value=versions[0])
        version_dropdown = ttk.Combobox(version_window, textvariable=selected_version, values=versions,
                                        state="readonly")
        version_dropdown.grid(row=0, column=1, padx=10, pady=10)

        # Download button
        def on_download():
            version = selected_version.get()
            version_window.destroy()
            download_specific_version(version)

        download_button = tk.Button(version_window, text="Download", command=on_download)
        download_button.grid(row=1, column=0, columnspan=2, pady=10)

    except requests.RequestException as e:
        messagebox.showerror("Error", f"Failed to fetch versions: {e}")


# Function to download and extract a specific version (reuse logic from the previous implementation, clean the folder before extracting)
def download_specific_version(version):
    download_popup = tk.Toplevel(root)
    download_popup.title(f"Downloading Dependency Check {version}")
    download_progress = tk.DoubleVar()
    progress_bar = ttk.Progressbar(download_popup, variable=download_progress, maximum=100, length=300)
    progress_bar.grid(row=0, column=0, padx=10, pady=10)

    def download_task():
        try:
            download_url = f"https://github.com/jeremylong/DependencyCheck/releases/download/v{version}/dependency-check-{version}-release.zip"
            response = requests.get(download_url, stream=True)
            total_size = int(response.headers.get('content-length', 0))

            if total_size == 0:
                messagebox.showerror("Download Error", "Failed to retrieve the file.")
                download_popup.destroy()
                return

            zip_file_path = f"dependency-check-{version}.zip"
            with open(zip_file_path, "wb") as file:
                downloaded_size = 0
                for data in response.iter_content(chunk_size=1024):
                    file.write(data)
                    downloaded_size += len(data)
                    download_progress.set((downloaded_size / total_size) * 100)
                    download_popup.update_idletasks()

                    # Clean the dependency-check folder, preserving the data directory
                    clean_dependency_check_folder()

            # Extract the downloaded ZIP file
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                zip_ref.extractall(".")

            # Delete the zip file after extraction
            if os.path.exists(zip_file_path):
                os.remove(zip_file_path)

            messagebox.showinfo("Download Complete",
                                f"Downloaded and extracted Dependency Check {version} to the current directory.")
            download_popup.destroy()
        except requests.RequestException as e:
            messagebox.showerror("Download Error", f"An error occurred while downloading: {e}")
            download_popup.destroy()

    threading.Thread(target=download_task).start()


# Function to run the dependency-check command
def start_scan():
    ensure_folders()  # Ensure folders exist before running the command

    # Disable the Start Scan button
    run_button.config(state=tk.DISABLED)

    source_path = source_entry.get()
    files = files_entry.get().split(";")
    project_name = project_name_entry.get()
    api_key = api_key_entry.get()
    dep_check_path = os.path.join("dependency-check", "bin", "dependency-check.bat")
    format = report_format.get().upper()  # Get the selected format and convert to lowercase

    # Validate mandatory fields
    if not source_path and not files:
        messagebox.showwarning("Invalid Input", "Please select a valid source path or files to scan.")
        run_button.config(state=tk.NORMAL)  # Re-enable the button
        return

    if not os.path.exists(dep_check_path):
        response = messagebox.askyesno("Dependency Check Not Found",
                                       "dependency-check.bat not found. Do you want to download the latest version?")
        if response:
            download_dependency_check()
        run_button.config(state=tk.NORMAL)  # Re-enable the button
        return

    if not project_name:
        messagebox.showwarning("Missing Project Name", "The Project Name field is mandatory.")
        run_button.config(state=tk.NORMAL)  # Re-enable the button
        return

    # Prepare file paths
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file_path = os.path.join("reports", f"{project_name}_{timestamp}.{format}")
    log_file_path = os.path.join("logs", f"{project_name}_{timestamp}.log")

    # Prepare command
    command = f'"{dep_check_path}"'
    # Add source_path argument if it's not empty
    if source_path:
        command += f' -s "{source_path}"'
    # Add each file argument if files is not empty
    for file in files:
        if file:  # Ensure file is not empty
            command += f' -s "{file}"'
    # Add other required arguments
    command += f' --project "{project_name}" --nvdApiKey "{api_key}" --out "{output_file_path}" --format "{format}"'

    def execute_command():
        try:
            with open(log_file_path, "w") as log_file:
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           text=True)
                for line in process.stdout:
                    log_file.write(line)
                    output_text.configure(state='normal')
                    output_text.insert(tk.END, line)
                    output_text.configure(state='disabled')
                    # Autoscroll to the bottom
                    output_text.yview(tk.END)
                    output_text.see(tk.END)
                process.wait()
                if process.returncode == 0:
                    messagebox.showinfo("Success", f"Scan completed successfully. Report saved to {output_file_path}")
                else:
                    error_message = process.stderr.read()
                    log_file.write(error_message)
                    messagebox.showerror("Error", error_message)
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", e.stderr.decode())
        finally:
            run_button.config(state=tk.NORMAL)  # Re-enable the button after execution

    threading.Thread(target=execute_command).start()


# Function to show about information
def show_about():
    messagebox.showinfo("About Developer", "DependencyCheckGUI\n\nVersion 1.1\n\nDeveloper: Vaibhav Patil"
                                           "\n\nThis tool provides User Interface for Windows Users to download and run OWASP dependency-check command line tools and generate reports."
                                           "\n\nIt is an attempt to ease the use of OWASP Dependency Check command line tools with user friendly UI.")


# Function to exit the program
def exit_program():
    root.quit()


# Funtiona to show the API key information
def show_api_info():
    # Create a new window for the popup
    popup = tk.Toplevel()
    popup.title("NVD API Key Information")

    # Set the window size and minimum size
    popup.geometry("400x250")
    popup.minsize(400, 370)

    # Configure the background color
    popup.configure(bg="#f0f0f0")

    # Display the message with instructions
    message = (
        "NVD API key is a unique identifier that allows users to access and query "
        "the National Vulnerability Database (NVD). Without an NVD API Key dependency-check's updates will be extremely slow. The NVD API has enforced rate limits. If you are using a single API KEY and multiple builds occur you could hit the rate limit and receive 403 errors.\n\n"
        "How to get an API key:\n"
        "Users can request an API key at https://nvd.nist.gov/developers/request-an-api-key\n\n"
        "Don't have an API key? Click OK to visit NVD website to request an API key "
    )

    label = tk.Label(popup, text=message, wraplength=350, justify="left", padx=10, pady=10,
                     bg="#f0f0f0", font=("Helvetica", 10), anchor="w")
    label.pack(padx=20, pady=20)

    # Function to handle the OK button click
    def on_ok():
        webbrowser.open("https://nvd.nist.gov/developers/request-an-api-key")
        popup.destroy()  # Close the popup

    # Function to handle the Cancel button click
    def on_cancel():
        popup.destroy()  # Close the popup

    # Create OK and Cancel buttons with styling
    button_frame = tk.Frame(popup, bg="#f0f0f0")
    button_frame.pack(pady=10)

    ok_button = tk.Button(button_frame, text="OK", command=on_ok, width=10, height=2,
                          bg="#4CAF50", fg="white", font=("Helvetica", 10, "bold"), relief="raised")
    ok_button.pack(side=tk.LEFT, padx=20)

    cancel_button = tk.Button(button_frame, text="Cancel", command=on_cancel, width=10, height=2,
                              bg="#F44336", fg="white", font=("Helvetica", 10, "bold"), relief="raised")
    cancel_button.pack(side=tk.LEFT, padx=10)

    # Run the popup
    popup.mainloop()


#########################################################################

# Function to browse folder and select directory
def browse_folder(folder_entry):
    folder_path = filedialog.askdirectory(title="Select Folder to Scan")
    if folder_path:
        folder_entry.delete(0, tk.END)
        folder_entry.insert(0, folder_path)


# Function to log messages to the log text widget
def log(log_text, message):
    log_text.insert(tk.END, message + "\n")
    log_text.update_idletasks()


# Function to process files and generate the required data
def process_files(folder_path, report_filename, log_text):
    output_data = []
    file_count = 0

    # Initialize log
    log(log_text, "Starting scan...")

    try:
        sha1_file = open('sha1.txt', 'w+')
        rawdata = open('sha1.txt', 'w')

        for path, subdirs, files in os.walk(folder_path):
            for filename in files:
                file_count += 1
                jarfile = os.path.join(path, filename)

                if "jar" in filename:
                    sha1_hash = compute_sha1(jarfile)
                    raw = sha1_hash + " " + filename
                    rawdata.write(raw + '\n')
                    log(log_text, f"Processed: {filename}\n")

        rawdata.close()

        output_data = analyze_sha1_data(log_text)

        # Export to the user-provided filename
        if output_data:
            df = pd.DataFrame(output_data)
            os.makedirs("SCA_Templates_Jar", exist_ok=True)

            output_file = os.path.join("SCA_Templates_Jar", f"{report_filename}.xlsx")
            df.to_excel(output_file, index=False)
            log(log_text, f"Exported data to {output_file}")

        else:
            log(log_text, "No data to export.")

        messagebox.showinfo("Scan Complete",
                            f"Scan finished. Processed {file_count} files. File is saved at {output_file}")

    except Exception as e:
        log(log_text, f"Error: {str(e)}")
        messagebox.showerror("Error", f"An error occurred: {str(e)}")


def compute_sha1(jarfile):
    with open(jarfile, 'rb') as f:
        return hashlib.sha1(f.read()).hexdigest()


def analyze_sha1_data(log_text):
    output_data = []

    with open('sha1.txt', 'r') as f:
        for line in f.readlines():
            sha = line.split(" ")[0]
            jar = line.split(" ")[1]

            search_url = f'http://search.maven.org/solrsearch/select?q=1:{sha}&rows=20&wt=json'
            search_url = urllib.parse.quote(search_url, safe=":/?&=.")

            page = urlopen(search_url)
            data = json.loads(b"".join(page.readlines()))

            if data["response"] and data["response"]["numFound"] > 0:
                jarinfo = data["response"]["docs"][0]
                latest_version = get_latest_version(jarinfo)
                output_data.append(build_output_entry(jar, jarinfo, latest_version))
                log(log_text, f"Found info for {jar}")
            else:
                output_data.append(build_empty_output_entry(jar))
                log(log_text, f"Info Not found for {jar}")

    return output_data


def get_latest_version(jarinfo):
    latest_version_url = f'https://search.maven.org/solrsearch/select?q=g:"{urllib.parse.quote(jarinfo["g"])}" AND a:"{urllib.parse.quote(jarinfo["a"])}"&core=gav&rows=20&wt=json'
    latest_version_url = urllib.parse.quote(latest_version_url, safe=":/?&=.")

    res = urlopen(latest_version_url)
    data_response = json.loads(b"".join(res.readlines()))

    if data_response["response"] and data_response["response"]["numFound"] > 0:
        mvn_response = data_response["response"]["docs"][0]
        latest_version_available = mvn_response["v"]
        latest_version_date = datetime.datetime.fromtimestamp(mvn_response["timestamp"] / 1000.0).date()  # Extract only date part
        return latest_version_available, str(latest_version_date)
    return "-", "-"


def build_output_entry(jar, jarinfo, latest_version):
    return {
        "LIBRARY NAME": jar,
        "eCW LIBRARY/THIRDPARTY LIBRARY": "",
        "ARTIFACT ID": jarinfo["a"],
        "Group ID": jarinfo["g"],
        "IS VULNERABLE LIBRARY": "",
        "LIBRARY CURRENT VERSION": jarinfo["v"],
        "RELEASE DATE OF LIBRARY(CURRENT VERSION)": str(datetime.datetime.fromtimestamp(jarinfo["timestamp"] / 1000.0).date()),  # Date only
        "RECENT MOST VERSION AVAILABLE": latest_version[0],
        "RELEASE DATE OF LIBRARY(RECENT MOST VERSION AVAILABLE)": latest_version[1],  # Date only
        "LIBRARY STATUS": "",
        "IS VULNERABLE RECENT MOST VERSION AVAILABLE": "",
        "CVE CURRENT VERSION": "",
        "SEVERITY OF CVE": "",
        "VULNERABILITY REFERENCE": "",
        "IS ECW PRODUCT AFFECTED/NOT AFFECTED": "",
        "RISK TO ECW": "",
        "COMMENT FOR ECW RISK": "",
        "LAST UPGRADED DATE IN ECW APPLICATION": "",
        "JIRA ID": "",
        "JIRA STATUS": "",
        "COMMENTS": "",
        "Additional Comments": ""
    }


def build_empty_output_entry(jar):
    return {
        "LIBRARY NAME": jar,
        "eCW LIBRARY/THIRDPARTY LIBRARY": "",
        "ARTIFACT ID": "-",
        "Group ID": "-",
        "IS VULNERABLE LIBRARY": "",
        "LIBRARY CURRENT VERSION": "-",
        "RELEASE DATE OF LIBRARY(CURRENT VERSION)": "-",
        "RECENT MOST VERSION AVAILABLE": "-",
        "RELEASE DATE OF LIBRARY(RECENT MOST VERSION AVAILABLE)": "-",
        "LIBRARY STATUS": "",
        "IS VULNERABLE RECENT MOST VERSION AVAILABLE": "",
        "CVE CURRENT VERSION": "",
        "SEVERITY OF CVE": "",
        "VULNERABILITY REFERENCE": "",
        "IS ECW PRODUCT AFFECTED/NOT AFFECTED": "",
        "RISK TO ECW": "",
        "COMMENT FOR ECW RISK": "",
        "LAST UPGRADED DATE IN ECW APPLICATION": "",
        "JIRA ID": "",
        "JIRA STATUS": "",
        "COMMENTS": "",
        "Additional Comments": ""
    }


# Open the scan window inside the existing GUI window
def open_scan_window(root):
    scan_window = tk.Toplevel(root)
    scan_window.title("Maven Jar Scan")

    # Ensure the scan window stays on the second level (not topmost)
    scan_window.attributes("-topmost", 0)  # scan window is not always on top
    scan_window.lift()  # Bring the scan window to the front

    # Make sure the main window stays behind
    root.attributes("-topmost", 0)

    # Create UI components for the scan window
    folder_label = tk.Label(scan_window, text="Select Folder to Scan:")
    folder_label.grid(row=0, column=0, padx=10, pady=5)

    folder_entry = tk.Entry(scan_window, width=50)
    folder_entry.grid(row=0, column=1, padx=10, pady=5)

    browse_button = tk.Button(scan_window, text="Browse", command=lambda: browse_folder(folder_entry))
    browse_button.grid(row=0, column=2, padx=10, pady=5)

    # Add label and entry field for report filename
    report_filename_label = tk.Label(scan_window, text="Report Filename:")
    report_filename_label.grid(row=1, column=0, padx=10, pady=5)

    report_filename_entry = tk.Entry(scan_window, width=50)
    report_filename_entry.grid(row=1, column=1, padx=10, pady=5)

    log_text = tk.Text(scan_window, height=20, width=80)
    log_text.grid(row=3, column=0, columnspan=3, padx=10, pady=10)

    def start_solar_scan():
        folder_path = folder_entry.get()
        report_filename = report_filename_entry.get()

        if not folder_path:
            messagebox.showwarning("No Folder Selected", "Please select a folder.")
            return

        if not report_filename:
            messagebox.showwarning("No Report Filename", "Please provide a report filename.")
            return

        # Run the scanning process in a new thread
        threading.Thread(target=process_files, args=(folder_path, report_filename, log_text), daemon=True).start()

    scan_button = tk.Button(scan_window, text="Start Scan", command=start_solar_scan)
    scan_button.grid(row=2, column=1, pady=20)


#########################################################################
# Create CVE details retrieval GUI
def retriev_CVE_details_gui():
    # Create the second window for retrieving CVE details
    window_b = tk.Toplevel()
    window_b.title("CVE Details Retriever")

    # Configure the window
    frame = ttk.Frame(window_b, padding="10")
    frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    label = ttk.Label(frame, text="Enter CVE IDs (comma separated):")
    label.grid(row=0, column=0, sticky=tk.W)

    entry = ttk.Entry(frame, width=50)
    entry.grid(row=0, column=1, sticky=(tk.W, tk.E))

    result_text = tk.Text(frame, wrap='word', width=100, height=20)
    result_text.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))

    result_text.tag_configure('bold', font=('Helvetica', 10, 'bold'))

    # Button to retrieve CVE details
    button = ttk.Button(frame, text="Retrieve CVE Details",
                        command=lambda: retrieve_cve_details(entry.get().split(','), result_text))
    button.grid(row=0, column=2, sticky=tk.W)

    # Scrollbar for the text area
    scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=result_text.yview)
    result_text.configure(yscroll=scrollbar.set)
    scrollbar.grid(row=1, column=3, sticky=(tk.N, tk.S))


# Function to retrieve and display CVE details
def retrieve_cve_details(cve_ids, result_text):
    cve_ids = [cve_id.strip() for cve_id in cve_ids]
    if not cve_ids or cve_ids[0] == '':
        messagebox.showwarning("Input Error", "Please enter at least one CVE ID.")
        return

    result_text.delete(1.0, tk.END)  # Clear previous results

    for cve_id in cve_ids:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        try:
            response = requests.get(url)
            response.raise_for_status()
            cve_details = response.json()
            display_cve_details(cve_details, result_text)
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Error retrieving CVE details for {cve_id}: {e}")


def format_date(date_string):
    return date_string.split('T')[0] if date_string else 'N/A'


def display_cve_details(cve_details, result_text):
    if cve_details.get('vulnerabilities'):
        for vulnerability in cve_details['vulnerabilities']:
            cve = vulnerability['cve']
            cve_id = cve.get('id', 'N/A')
            description = cve.get('descriptions', [{'value': 'N/A'}])[0]['value']
            published_date = format_date(cve.get('published'))
            last_modified_date = format_date(cve.get('lastModified'))

            metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {})
            severity = metrics.get('baseSeverity', 'N/A')
            vector = metrics.get('vectorString', 'N/A')
            base_score = metrics.get('baseScore', 'N/A')

            result_text.configure(state='normal')
            result_text.insert(tk.END, "CVE ID: ", 'bold')
            result_text.insert(tk.END, f"{cve_id}\n")
            result_text.insert(tk.END, "Description: ", 'bold')
            result_text.insert(tk.END, f"{description}\n")
            result_text.insert(tk.END, "Published Date: ", 'bold')
            result_text.insert(tk.END, f"{published_date}\n")
            result_text.insert(tk.END, "Last Modified Date: ", 'bold')
            result_text.insert(tk.END, f"{last_modified_date}\n")
            result_text.insert(tk.END, "Severity: ", 'bold')
            result_text.insert(tk.END, f"{severity}\n")
            result_text.insert(tk.END, "Vector: ", 'bold')
            result_text.insert(tk.END, f"{vector}\n")
            result_text.insert(tk.END, "Base Score: ", 'bold')
            result_text.insert(tk.END, f"{base_score}\n\n")
            result_text.configure(state='disabled')
            # Autoscroll to the bottom
            result_text.yview(tk.END)

    else:
        messagebox.showinfo("No Data", "No vulnerabilities found for the given CVE ID.")


####################################################################################

# Function to browse for the first CSV file (DependencyName, CVE, and CVSSv3_BaseSeverity columns)
def browse_first_csv(first_csv_entry):
    filepath = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    if filepath:
        first_csv_entry.delete(0, tk.END)
        first_csv_entry.insert(0, filepath)


# Function to browse for the second Excel file (LIBRARY NAME, CVE CURRENT VERSION, and SEVERITY OF CVE columns)
def browse_second_excel(second_excel_entry):
    filepath = filedialog.askopenfilename(filetypes=[("Excel files", "*.xlsx")])
    if filepath:
        second_excel_entry.delete(0, tk.END)
        second_excel_entry.insert(0, filepath)


# Function to get the highest severity
def get_highest_severity(severities):
    severity_order = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4}
    # Sort severities based on the predefined order and return the highest one (lowest number)
    sorted_severities = sorted(severities, key=lambda x: severity_order.get(x, 5))  # Default 5 for unknown severities
    return sorted_severities[0] if sorted_severities else None


# Function to check if the new value is already in the existing value (to avoid duplicates)
def check_and_append(existing_value, new_value):
    if pd.isna(existing_value):
        return new_value
    elif new_value not in existing_value:
        return existing_value + ", " + new_value
    return existing_value  # If the value already exists, don't append it


# Function to process the CSV and Excel files and append CVEs and severity to the Excel file
def process_template_files(first_csv_entry, second_excel_entry):
    try:
        # Get file paths from the entries
        first_csv_path = first_csv_entry.get()
        second_excel_path = second_excel_entry.get()

        # Read the first CSV file using Pandas
        df_first = pd.read_csv(first_csv_path)

        # Read the second Excel file using Pandas
        df_second = pd.read_excel(second_excel_path)

        # Group CVEs by DependencyName (which contains the .jar file names) in the first CSV
        cve_groups = df_first.groupby('DependencyName')['CVE'].apply(lambda x: ', '.join(x)).to_dict()

        # Group severities by DependencyName
        severity_groups = df_first.groupby('DependencyName')['CVSSv3_BaseSeverity'].apply(list).to_dict()

        # Ensure required columns exist in the second Excel file
        required_columns = [
            'CVE CURRENT VERSION', 'SEVERITY OF CVE', 'VULNERABILITY REFERENCE',
            'IS ECW PRODUCT AFFECTED/NOT AFFECTED', 'RISK TO ECW', 'COMMENT FOR ECW RISK',
            'LAST UPGRADED DATE IN ECW APPLICATION', 'JIRA ID', 'JIRA STATUS', 'COMMENTS', 'Additional Comments',
            'IS VULNERABLE LIBRARY', 'ARTIFACT ID', 'eCW LIBRARY/THIRDPARTY LIBRARY'
        ]

        for col in required_columns:
            if col not in df_second.columns:
                df_second[col] = ""

        # Iterate through each row in the second Excel file
        for index, row in df_second.iterrows():
            jar_file = row['LIBRARY NAME']  # Assumed column name for JAR files in the second Excel

            # Check the ARTIFACT ID to determine the library type
            artifact_id = row['ARTIFACT ID']
            if artifact_id == "-":
                df_second.at[index, 'eCW LIBRARY/THIRDPARTY LIBRARY'] = 'eCW'
            else:
                df_second.at[index, 'eCW LIBRARY/THIRDPARTY LIBRARY'] = 'Third Party'

            if jar_file in cve_groups:
                # If the JAR file is found, append the CVEs to the 'CVE CURRENT VERSION' column
                existing_cves = row['CVE CURRENT VERSION']
                new_cves = cve_groups[jar_file]

                # Check and append CVEs only if they are not already present
                df_second.at[index, 'CVE CURRENT VERSION'] = check_and_append(existing_cves, new_cves)

                # Get the highest severity for the JAR file
                if jar_file in severity_groups:
                    severities = severity_groups[jar_file]
                    highest_severity = get_highest_severity(severities)

                    # Check and append the highest severity only if it's not already present
                    existing_severity = row['SEVERITY OF CVE']
                    df_second.at[index, 'SEVERITY OF CVE'] = check_and_append(existing_severity, highest_severity)

                # Update 'IS VULNERABLE LIBRARY' to 'Yes' if CVE is present
                if pd.notna(df_second.at[index, 'CVE CURRENT VERSION']):
                    df_second.at[index, 'IS VULNERABLE LIBRARY'] = 'Yes'
            else:
                # If no CVE is found, set all the specified columns to "NA", but set 'IS VULNERABLE LIBRARY' to "No"
                df_second.at[index, 'CVE CURRENT VERSION'] = "NA"
                df_second.at[index, 'SEVERITY OF CVE'] = "NA"
                df_second.at[index, 'VULNERABILITY REFERENCE'] = "NA"
                df_second.at[index, 'IS ECW PRODUCT AFFECTED/NOT AFFECTED'] = "NA"
                df_second.at[index, 'RISK TO ECW'] = "NA"
                df_second.at[index, 'COMMENT FOR ECW RISK'] = "NA"
                df_second.at[index, 'LAST UPGRADED DATE IN ECW APPLICATION'] = "NA"
                df_second.at[index, 'JIRA ID'] = "NA"
                df_second.at[index, 'JIRA STATUS'] = "NA"
                df_second.at[index, 'COMMENTS'] = "NA"
                df_second.at[index, 'Additional Comments'] = "NA"
                df_second.at[index, 'IS VULNERABLE LIBRARY'] = "No"  # Updated to "No" instead of "NA"

        # Save the updated second Excel file
        df_second.to_excel(second_excel_path, index=False)
        messagebox.showinfo("Success",
                            "CVE, Severity, IS VULNERABLE LIBRARY, and other columns have been successfully updated.")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")



# Function to browse for the first CSV file (Jar Metadata)
def browse_first_csv(first_csv_entry):
    current_dir = os.getcwd()  # Get the current working directory
    sca_templates_jar_folder = os.path.join(current_dir, 'reports')  # Define the folder path
    filepath = filedialog.askopenfilename(initialdir=sca_templates_jar_folder, filetypes=[("CSV files", "*.csv")])
    if filepath:
        first_csv_entry.delete(0, tk.END)
        first_csv_entry.insert(0, filepath)


# Function to browse for the second Excel file (SCA Jar Template)
def browse_second_excel(second_excel_entry):
    current_dir = os.getcwd()  # Get the current working directory
    reports_folder = os.path.join(current_dir, 'SCA_Templates_Jar')  # Define the folder path
    filepath = filedialog.askopenfilename(initialdir=reports_folder, filetypes=[("Excel files", "*.xlsx")])
    if filepath:
        second_excel_entry.delete(0, tk.END)
        second_excel_entry.insert(0, filepath)


# Function to open the new window
def Process_SCA_template():
    # Create a new top-level window
    cve_window = tk.Toplevel(root)
    cve_window.title("SCA Jar Template Processor")
    cve_window.geometry("600x400")  # A bit larger to allow space for all elements
    cve_window.resizable(True, True)  # Allow resizing in both directions

    # Create the GUI components for the file processing window
    frame = tk.Frame(cve_window)
    frame.pack(pady=20)

    # First CSV File Entry and Browse Button
    first_csv_label = tk.Label(frame, text="Select Jar DC Report (CSV):")
    first_csv_label.grid(row=0, column=0, padx=10, pady=5)
    first_csv_entry = tk.Entry(frame, width=40)
    first_csv_entry.grid(row=0, column=1, padx=10, pady=5)
    first_csv_button = tk.Button(frame, text="Select", command=lambda: browse_first_csv(first_csv_entry))
    first_csv_button.grid(row=0, column=2, padx=10, pady=5)

    # Second Excel File Entry and Browse Button
    second_excel_label = tk.Label(frame, text="Select SCA Jar Template (Excel):")
    second_excel_label.grid(row=1, column=0, padx=10, pady=5)
    second_excel_entry = tk.Entry(frame, width=40)
    second_excel_entry.grid(row=1, column=1, padx=10, pady=5)
    second_excel_button = tk.Button(frame, text="Select", command=lambda: browse_second_excel(second_excel_entry))
    second_excel_button.grid(row=1, column=2, padx=10, pady=5)

    # Process Button
    process_button = tk.Button(cve_window, text="Update SCA Jar Template", width=20,
                               command=lambda: process_template_files(first_csv_entry, second_excel_entry))
    process_button.pack(pady=20)


####################################################################################
# Create the main window
root = tk.Tk()
root.title("Dependency Check Runner")
menu_bar = tk.Menu(root)
root.config(menu=menu_bar)

# File menu
file_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="Open Reports", command=lambda: open_folder("Reports"))
file_menu.add_command(label="Open Logs", command=lambda: open_folder("Logs"))
file_menu.add_command(label="Open SCA Jar Templates", command=lambda: open_folder("SCA_Templates_Jar"))
file_menu.add_command(label="Exit", command=exit_program)

# Options menu
options_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Options", menu=options_menu)
options_menu.add_command(label="Update DC Tools to Latest Version", command=download_dependency_check)
options_menu.add_command(label="Download Other Version of DC Tools", command=open_version_selection_window)
options_menu.add_command(label="Purge NVD Data", command=purge_NVD_data)

# Tools menu
tools_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Tools", menu=tools_menu)
tools_menu.add_command(label="Generate SCA Jar Template", command=lambda: open_scan_window(root))
tools_menu.add_command(label="Update SCA Jar Template", command=Process_SCA_template)
tools_menu.add_command(label="Retrieve CVE Details", command=retriev_CVE_details_gui)

# Help menu
help_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Help", menu=help_menu)
help_menu.add_command(label="Check Version of DC Tools", command=check_version)
help_menu.add_command(label="About Us", command=show_about)

tk.Label(root, text="Select folder to scan:").grid(row=0, column=0, padx=10, pady=5)
source_entry = tk.Entry(root, width=50)
source_entry.grid(row=0, column=1, padx=10, pady=5)
browse_button = tk.Button(root, text="Select", command=browse_source_path)
browse_button.grid(row=0, column=2, padx=10, pady=5)

tk.Label(root, text="Select files to scan:").grid(row=1, column=0, padx=10, pady=5)
files_entry = tk.Entry(root, width=50)
files_entry.grid(row=1, column=1, padx=10, pady=5)
browse_files_button = tk.Button(root, text="Select", command=browse_files)
browse_files_button.grid(row=1, column=2, padx=10, pady=5)

tk.Label(root, text="Enter NVD API Key :").grid(row=2, column=0, padx=10, pady=5)
api_key_entry = tk.Entry(root, width=50)
api_key_entry.grid(row=2, column=1, padx=10, pady=5)
browse_files_button = tk.Button(root, text="Info", command=show_api_info)
browse_files_button.grid(row=2, column=2, padx=10, pady=5)

tk.Label(root, text="Enter Project Name:").grid(row=3, column=0, padx=10, pady=5)
project_name_entry = tk.Entry(root, width=50)
project_name_entry.grid(row=3, column=1, padx=10, pady=5)
# Add dropdown for output format selection
report_format = tk.StringVar()
report_format.set("HTML")  # default value
report_format_dropdown = ttk.Combobox(root, textvariable=report_format, values=["HTML", "CSV", "XML"], state="readonly")
report_format_dropdown.grid(row=3, column=2, padx=10, pady=5)

run_button = tk.Button(root, text="Start Scan", command=start_scan, )
run_button.grid(row=5, column=0, columnspan=3, pady=10)

output_text = ScrolledText(root, width=80, height=20)
output_text.grid(row=6, column=0, columnspan=3, padx=10, pady=10)

root.attributes("-topmost", 0)
root.mainloop()
