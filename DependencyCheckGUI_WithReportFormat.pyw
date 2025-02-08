import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk
import subprocess
import threading
import os
import requests
import zipfile
import shutil
import webbrowser
from datetime import datetime

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
        ("Supported files", "*.jar *.js *.lock *.h *.nuspec *.csproj *.vbproj *.zip *.ear *.war *.sar *.apk *.nupkg *.exe *.dll"),
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
        messagebox.showerror("Folder does not exist", f"Folder '{folder_name}' does not exist in the current directory.")

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
            
            messagebox.showinfo("Download Complete", f"Downloaded and extracted the latest version of Dependency Check to the current directory.")
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
        version_dropdown = ttk.Combobox(version_window, textvariable=selected_version, values=versions, state="readonly")
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

            messagebox.showinfo("Download Complete", f"Downloaded and extracted Dependency Check {version} to the current directory.")
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
        response = messagebox.askyesno("Dependency Check Not Found", "dependency-check.bat not found. Do you want to download the latest version?")
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
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
file_menu.add_command(label="Exit", command=exit_program)

# Options menu
options_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Options", menu=options_menu)
options_menu.add_command(label="Update DC Tools to Latest Version", command=download_dependency_check)
options_menu.add_command(label="Download Other Version of DC Tools", command=open_version_selection_window)
options_menu.add_command(label="Purge NVD Data", command=purge_NVD_data)

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

run_button = tk.Button(root, text="Start Scan", command=start_scan,)
run_button.grid(row=5, column=0, columnspan=3, pady=10)

output_text = ScrolledText(root, width=80, height=20)
output_text.grid(row=6, column=0, columnspan=3, padx=10, pady=10)

root.mainloop()
