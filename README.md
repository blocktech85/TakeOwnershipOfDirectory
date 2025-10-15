This PowerShell script is an advanced, interactive utility designed to **take ownership and reset permissions on directories and files**, while **creating full ACL (Access Control List) backups** and logging every action taken.  

It operates as a complete command-line tool with progress tracking, logging, backup safety mechanisms, and multiple fallback strategies to handle restricted files or system-protected objects.

---

### Program Overview

The script:
- Interactively asks the user for:
  - A **target directory or file** to process.
  - A **backup directory** for ACL data.
  - A **backup format** (JSON or XML).
- Then performs ownership and permission changes recursively on all contained files and subdirectories.

---

### Major Functional Components

#### 1. Interface Setup
- Clears the screen and prints detailed banners formatted with ASCII art.
- Expands the PowerShell window width for readability (150 characters wide).
- Displays a styled program title indicating it’s a “Program to Take Ownership of Directories/Files.”

#### 2. Logger Class
- Every operation and error is **timestamped and written both to the console and to a .log file**.
- Methods:
  - Write(msg) logs normal messages.
  - WriteError(msg) logs errors with [ERROR] tagging.

#### 3. ACLManager Class
Handles all security and ownership operations:

- **Properties Tracked**
  - Target path, backup directory, current user, retry limits, and last backup file paths.
- **Core Methods**
  - BackupACLs(): Recursively scans every file/subfolder of the target path, saves their ACLs (including SDDL strings) in either JSON or XML format, and stores a separate SDDL backup for the root folder.
  - UserHasFullControl(): Checks if the current user already has full control permissions.
  - ChangeOwnershipWithRetries(): Main operation loop that:
    - Iterates through all target files/folders.
    - Uses 	akeown.exe and icacls commands to transfer ownership to the current user.
    - Enables inheritance and grants full control recursively.
    - Retries multiple times with delays if it encounters errors or access denial.
  - **Fallback Strategies**
    - TakeOwnershipFallbackParent(): Takes ownership of a file’s parent directory if direct file access fails.
    - TakeOwnershipAsSystem(): Creates a temporary **SYSTEM-level scheduled task** that retries ownership transfer using elevated permissions.

All progress is displayed with PowerShell’s Write-Progress bar.

#### 4. Input Validation Functions
- Get-ValidatedPath(): Ensures user inputs correspond to valid or accessible file paths.
- Get-BackupFormat(): Prompts for backup format, defaulting to JSON if the user presses Enter.

---

### Workflow Summary

1. **Initialization:**
   - User inputs a directory to take ownership of.
   - Backup directory and format are set.
   - Log file path is generated with timestamp naming.

2. **Backup:**
   - ACLs (security descriptors) of all items are backed up before any modifications.

3. **Taking Ownership:**
   - File ownership is changed to the current logged-in user using 	akeown.exe and Set-Acl.
   - Permissions are reset recursively with inheritance turned on and full control granted.
   - Retries automatically if ownership fails, including system-level fallback escalation.

4. **Completion Summary:**
   - Clears the screen and prints a color-coded report showing:
     - Target path processed.
     - Total items processed and successful ownership transfers.
     - File paths for ACL and SDDL backups.
     - Log file location.
     - List of any failed items (in red).

---

### Output Artifacts

After completion, three files are created in the chosen backup directory:
- **ACL JSON/XML Backup** — all item ACLs for recovery.
- **Root SDDL text file** — simple text backup of the root folder's ACL string.
- **Log file** — complete chronological log of operations, retries, and errors.

---

### Intended Use

This script is suitable for **system administrators or power users** who need to:
- Repair inaccessible folders.
- Reclaim ownership from SYSTEM or TrustedInstaller.
- Prepare ACL backups before making system-level security changes.
- Safely restore ownership permissions after a migration or OS reinstallation.
