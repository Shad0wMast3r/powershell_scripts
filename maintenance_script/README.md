# Ultimate Windows Administration Script

## Requirements

- **Windows PowerShell Version**: 5.0 or newer
- **Administrator Privileges**: Script must be run with elevated permissions
- **Required Modules**:
  - `ActiveDirectory`: For Active Directory-related operations
  - `Microsoft.Update.Session`: For Windows Update checks

---

## Overview

This PowerShell script is a comprehensive tool designed for system administrators to automate and streamline key administrative tasks on Windows systems. It consolidates multiple functions into a single script, eliminating the need for separate tools and manual steps.

---

## Features

### 1. **Hard Drive Check**
- Retrieves detailed information about all connected drives, including:
  - Drive letters
  - Total size, available space, and percentage of used space
  - Health and operational status of drives

### 2. **Event Viewer Analysis**
- Analyzes Event Viewer logs for:
  - Critical events
  - Error events
- Focuses on **Application** and **System** logs to aid in troubleshooting.

### 3. **Windows Updates**
- Lists all installed Windows updates.
- Option to fetch details of pending updates (if any).

### 4. **Reset Active Directory User Password**
- Facilitates password resets with two options:
  1. Generate and assign a secure temporary password. Users can specify the password length (minimum 8 characters).
  2. Set a custom password provided by the user.
- Automatically unlocks accounts and forces password changes at the next logon.
- Synchronizes the domain to ensure changes are reflected.

### 5. **USB Device History**
- Scans the Windows registry to retrieve the history of previously connected USB devices for auditing purposes.

### 6. **Uninstall Installed Software**
- Lists all installed software on the system, providing details such as:
  - Program names
  - Versions
  - Publishers
- Useful for software auditing and maintenance.

### 7. **Delete IIS Log Files**
- Automates the cleanup of IIS log files by:
  - Allowing a user-specified retention period (e.g., 30, 60, or up to 365 days).
  - Deleting files older than the specified retention period to free up disk space.

### 8. **Inactive AD User List**
- Identifies and lists all Active Directory accounts inactive for 90 days or more.
- Exports the list to a `.csv` file for reporting or follow-up actions.

### 9. **Hash Check**
- Allows users to compare file hashes using MD5, SHA1, and SHA256 algorithms.
- Prompts the user to:
  1. Specify the directory containing the files.
  2. Select two files for comparison.
- Clearly displays whether the hashes are identical or different for each algorithm.

### **Exit Script**
- Press **`q`** at any time to safely exit the script.
- Ensures session history is cleared before exiting to maintain privacy.

---

## How to Use the Script

### Instructions

1. **Open PowerShell as Administrator**
   - Right-click on the PowerShell shortcut and choose **"Run as Administrator"**.
   - Ensure the script has the required permissions to perform its operations.

2. **Run the Script**
   - Navigate to the directory containing the script.
   - Execute the script using the following command:
     ```powershell
     .\UltimateAdminScript.ps1
     ```

3. **Select a Task from the Menu**
   - After running the script, a menu will appear with numbered options.
   - Select an option by typing the corresponding number and pressing **Enter**.
   - To exit the script, press **`q`**.

4. **Follow the Prompts**
   - Depending on your selection, the script may ask for additional input:
     - For example, when deleting IIS logs, you will be asked to specify the retention period in days.
     - When comparing file hashes, you will be prompted to choose two files for comparison.

5. **Review Output**
   - The script provides detailed output for each action, including results or exported data.
   - For tasks like listing inactive Active Directory users, a `.csv` file will be created on your desktop for further review.

6. **Return to the Main Menu**
   - After completing a task, the script will return to the main menu for further selections.
   - Type **`q`** to end the session if no additional tasks are required.

---

## Author

**Author**: Andy 'shadowMast3r' Kukuc  
**GitHub**: [Follow me on GitHub](https://github.com/Shad0wMast3r)

---

## Disclaimer

This script is provided "as is" with no guarantees of completeness, accuracy, or reliability. Use at your own risk. The author is not liable for any unintended consequences or damage caused by this script.
