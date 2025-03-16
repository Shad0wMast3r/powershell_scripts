#Requires -RunAsAdministrator
<#
Written By Andy 'shadowMast3r' Kukuc
Follow me on Github
This is an ultimate script that I decided to over-engineer and over-complicate.
#>
Clear-History
Clear-Host

# Check the current execution policy
$currentPolicy = Get-ExecutionPolicy

# Allowed execution policies for script running
$allowedPolicies = @('RemoteSigned', 'Unrestricted', 'Bypass')

if (-not ($currentPolicy -in $allowedPolicies)) {
    Write-Host "The current execution policy is '$currentPolicy', which prevents the script from running."
    $changePolicy = Read-Host "Would you like to set the execution policy to 'RemoteSigned' to run the script? (Y/N)"

    if ($changePolicy -match '^[Yy]$') {
        try {
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
            Write-Host "The execution policy has been temporarily set to 'RemoteSigned'. Re-running the script..." -ForegroundColor Green
            Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy RemoteSigned -File `"$($MyInvocation.MyCommand.Definition)`"" -Verb RunAs
            exit
        }
        catch {
            Write-Host "Failed to change the execution policy. Please ensure you have the required privileges." -ForegroundColor Red
            exit
        }
    }
    else {
        Write-Host "The script cannot run without an appropriate execution policy. Please adjust the execution policy manually and re-run the script." -ForegroundColor Yellow
        exit
    }
}

# Variables
$last_reboot = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime | Get-Date

# Menu Loop
Do {
    # Display System Information
    Write-Host "Computer Name: $((Get-CimInstance -ClassName Win32_ComputerSystem).Name)"
    Write-Host "Operating System: $((Get-CimInstance -ClassName Win32_OperatingSystem).Caption)"
    Write-Host "Windows Version: $((Get-CimInstance -ClassName Win32_OperatingSystem).Version)"
    Write-Host "Windows Build: $((Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber)"
    Write-Host "Last Reboot: $last_reboot"

    # Display menu and read user input
    $user_input = Read-Host -Prompt "Please enter a selection`n1. Check Hard Drives`n2. Check Event Viewer`n3. Windows Updates`n4. Reset User Password`n5. Grab USB Device History`n6. Uninstall Software`n7. Delete IIS Log Files Older Than X Days`n8. List of old AD Users`n9. Compare File Hashes`nq. Exit"

    Switch ($user_input) {
        1 {
            # Check Hard Drives
            Write-Host "Checking Hard Drive Information..."
            try {
                $drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | Select-Object Name
                foreach ($drive in $drives) {
                    $volume = Get-Volume -DriveLetter $drive.Name.TrimEnd(":")
                    
                    if ($volume) {
                        # Output drive information with valid ForegroundColor
                        Write-Host ("Drive: {0}" -f $volume.DriveLetter) -ForegroundColor Cyan
                        Write-Host ("Size: {0:N2} GB" -f ($volume.Size / 1GB)) -ForegroundColor Yellow
                        Write-Host ("Free Space: {0:N2} GB" -f ($volume.SizeRemaining / 1GB)) -ForegroundColor Green
                        Write-Host ("Usage: {0:N1}%" -f (($volume.Size - $volume.SizeRemaining) / $volume.Size * 100)) -ForegroundColor Red
                        Write-Host "---"
                    }
                    else {
                        Write-Host ("Unable to retrieve information for drive {0}" -f $drive.Name.TrimEnd(':')) -ForegroundColor DarkYellow
                    }
                }
            }
            catch {
                Write-Host "An error occurred while retrieving hard drive information: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        2 {
            Write-Host "Scanning Event Viewer logs..."
        
            try {
                # Set up the filter range (from the first day of the current month to now)
                $first_of_the_month = (Get-Date).AddDays( - ((Get-Date).Day - 1)).Date
                Write-Host "The script will scan Event Viewer logs from $first_of_the_month to $(Get-Date)."
        
                # Prompt user for event type to filter
                Write-Host "Select the event type to filter:" -ForegroundColor Cyan
                Write-Host "1. Critical" -ForegroundColor Yellow
                Write-Host "2. Error" -ForegroundColor Yellow
                Write-Host "3. Warning" -ForegroundColor Yellow
                Write-Host "4. Information" -ForegroundColor Yellow
                Write-Host "5. Audit Success" -ForegroundColor Yellow
                Write-Host "6. Audit Failure" -ForegroundColor Yellow
                $log_type = Read-Host "Enter the number corresponding to the desired event type"
        
                # Map the user selection to a valid event type
                Switch ($log_type) {
                    1 { $filter = "Critical" }
                    2 { $filter = "Error" }
                    3 { $filter = "Warning" }
                    4 { $filter = "Information" }
                    5 { $filter = "Audit Success" }
                    6 { $filter = "Audit Failure" }
                    Default {
                        Write-Host "Invalid selection! Returning to menu." -ForegroundColor Red
                        break
                    }
                }
        
                # Retrieve and display filtered events
                $events = Get-WinEvent -FilterHashtable @{
                    LogName          = 'System'
                    LevelDisplayName = $filter
                    StartTime        = $first_of_the_month
                } -ErrorAction SilentlyContinue
        
                if ($events.Count -eq 0) {
                    Write-Host "No $filter events found in the specified time range." -ForegroundColor Yellow
                }
                else {
                    Write-Host "Displaying the most recent $filter events:" -ForegroundColor Green
                    $events | Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-Table -AutoSize
        
                    # Option to export events to a CSV file
                    $export_choice = Read-Host "Would you like to export these events to a CSV file? (Y/N)"
                    if ($export_choice -match "[Yy]") {
                        $outputPath = "$env:USERPROFILE\Desktop\Filtered_Events_$($filter)_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').csv"
                        $events | Select-Object TimeCreated, Id, LevelDisplayName, Message | Export-Csv -Path $outputPath -NoTypeInformation
                        Write-Host "Events have been exported to $outputPath" -ForegroundColor Green
                    }
                    else {
                        Write-Host "Export cancelled. Returning to menu."
                    }
                }
            }
            catch {
                Write-Host "An error occurred while retrieving Event Viewer logs: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        3 {
            Write-Host "Currently installed updates:"
            Get-CimInstance -Class Win32_QuickFixEngineering | Format-Table -AutoSize
            $choice = Read-Host "Do you want to see pending updates? (Y/N)"
            If ($choice -match "[yY]") {
                $session = New-Object -ComObject Microsoft.Update.Session
                $searcher = $session.CreateUpdateSearcher()
                $pendingUpdates = $searcher.Search("IsInstalled=0").Updates
                $pendingUpdates | Select-Object Title | Format-Table -AutoSize
            }
            else {
                Write-Host "Returning to menu."
            }
        }
        4 {
            if (-not (Get-Command "Set-ADAccountPassword" -ErrorAction SilentlyContinue)) {
                Write-Host "Active Directory module is not available."
                Continue
            }
        
            $passwordOption = Read-Host "Choose an option: 1. Generate Temporary Password 2. Set Custom Password"
            if ($passwordOption -eq "1") {
                # Ask the user to specify the length of the random password
                $passwordLength = Read-Host "Enter the desired password length (minimum 8 characters)"
                if (-not [int]$passwordLength -or $passwordLength -lt 8) {
                    Write-Host "Invalid length. Password length must be at least 8 characters. Returning to menu." -ForegroundColor Red
                    Continue
                }
        
                # Generate a random password of the specified length
                $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+[]{}|;:,.<>?`~"
                $tempPassword = -join ((1..$passwordLength) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
                Write-Host "Temporary password: $tempPassword" -ForegroundColor Green
                
                $username = Read-Host "Enter the username"
                try {
                    Write-Host "Attempting to reset password for $username..."
                    Set-ADAccountPassword -Identity $username -NewPassword (ConvertTo-SecureString -AsPlainText $tempPassword -Force) -Reset
                    Unlock-ADAccount -Identity $username
                    Write-Host "Password reset and account unlocked successfully." -ForegroundColor Cyan
                }
                catch {
                    Write-Host "Failed to reset password for $username. Error: $($Error[0])" -ForegroundColor Red
                }
            }
            elseif ($passwordOption -eq "2") {
                $customPassword = Read-Host "Enter the new password"
                $username = Read-Host "Enter the username"
                try {
                    Write-Host "Attempting to reset password for $username..."
                    Set-ADAccountPassword -Identity $username -NewPassword (ConvertTo-SecureString -AsPlainText $customPassword -Force) -Reset
                    Write-Host "Password reset completed for $username." -ForegroundColor Cyan
                }
                catch {
                    Write-Host "Failed to reset password for $username. Error: $($Error[0])" -ForegroundColor Red
                }
            }
            else {
                Write-Host "Invalid selection. Returning to menu." -ForegroundColor Yellow
            }
        }        
        
        5 {
            Write-Host "Gathering previously connected USB devices..."
            try {
                Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' |
                Select-Object FriendlyName | Format-Table -AutoSize
            }
            catch {
                Write-Host "Failed to retrieve USB device history: $($_.Exception.Message)"
            }
        }
        6 {
            Write-Host "Gathering installed software..."
            try {
                # Retrieve the list of installed programs
                $installedPrograms = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
                Select-Object DisplayName, DisplayVersion, Publisher |
                Where-Object { $_.DisplayName -ne $null } # Filter out entries with no DisplayName
        
                if ($installedPrograms.Count -eq 0) {
                    Write-Host "No installed programs found." -ForegroundColor Yellow
                }
                else {
                    # Sort the programs alphabetically by DisplayName
                    $sortedPrograms = $installedPrograms | Sort-Object DisplayName
        
                    # Display the sorted list of programs with index numbers
                    for ($i = 0; $i -lt $sortedPrograms.Count; $i++) {
                        Write-Host "$($i + 1). $($sortedPrograms[$i].DisplayName) ($($sortedPrograms[$i].DisplayVersion)) - Publisher: $($sortedPrograms[$i].Publisher)"
                    }
        
                    # Ask the user to pick a program by index
                    $selection = Read-Host "Enter the number corresponding to the software you want to uninstall (or type '0' to cancel)"
                    
                    if ([int]$selection -eq 0) {
                        Write-Host "Uninstallation cancelled. Returning to menu."
                    }
                    elseif ([int]$selection -gt 0 -and [int]$selection -le $sortedPrograms.Count) {
                        $programToUninstall = $sortedPrograms[[int]$selection - 1] # Get the selected program
                        Write-Host "You selected: $($programToUninstall.DisplayName)"
                        
                        # Attempt to uninstall the selected program
                        try {
                            $uninstallPath = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", 
                                "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
                                | Where-Object { $_.DisplayName -eq $programToUninstall.DisplayName }).UninstallString
                            if ($uninstallPath) {
                                Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$uninstallPath`"" -Wait
                                Write-Host "$($programToUninstall.DisplayName) has been uninstalled." -ForegroundColor Green
                            }
                            else {
                                Write-Host "Could not find the uninstall string for $($programToUninstall.DisplayName)." -ForegroundColor Red
                            }
                        }
                        catch {
                            Write-Host "Failed to uninstall $($programToUninstall.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                    else {
                        Write-Host "Invalid selection. Returning to menu."
                    }
                }
            }
            catch {
                Write-Host "Error retrieving software list: $($_.Exception.Message)"
            }
        }        
        
        7 {
            $days = Read-Host "Enter the number of days (max 365)"
            if ([int]$days -gt 0 -and [int]$days -le 365) {
                Get-ChildItem 'C:\inetpub\logs\LogFiles\*' -Recurse |
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$days) } |
                Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                Write-Host "Log files older than $days days deleted."
            }
            else {
                Write-Host "Invalid input. Days must be between 1 and 365."
            }
        }
        8 {
            if (-not (Get-Command "Get-ADUser" -ErrorAction SilentlyContinue)) {
                Write-Host "Active Directory module not available."
                Continue
            }
            $inactiveUsers = Get-ADUser -Filter * -Properties LastLogonDate |
            Where-Object { $_.LastLogonDate -lt (Get-Date).AddDays(-90) } |
            Select-Object Name, SamAccountName, LastLogonDate
            $outputPath = "$env:USERPROFILE\Desktop\Inactive_AD_Users.csv"
            $inactiveUsers | Export-Csv -Path $outputPath -NoTypeInformation
            Write-Host "Inactive users exported to $outputPath."
        }
        9 {
            Write-Host "Comparing File Hashes..."
        
            try {
                # Prompt user to provide a directory or default to the script's location
                $directory = Read-Host "Enter the directory path (leave blank to use the script's directory)"
                if ([string]::IsNullOrWhiteSpace($directory)) {
                    $directory = Split-Path -Parent $MyInvocation.MyCommand.Path
                    Write-Host "Using the script's directory: $directory" -ForegroundColor Green
                }
        
                # Verify that the directory exists
                if (-not (Test-Path -Path $directory)) {
                    Write-Host "The specified directory does not exist. Please try again." -ForegroundColor Red
                    Continue
                }
        
                # List files in the directory
                $files = Get-ChildItem -Path $directory -File
                if ($files.Count -eq 0) {
                    Write-Host "No files found in the specified directory. Returning to menu." -ForegroundColor Yellow
                    Continue
                }
        
                # Display available files
                Write-Host "Available files:" -ForegroundColor Cyan
                for ($i = 0; $i -lt $files.Count; $i++) {
                    Write-Host "$($i + 1). $($files[$i].Name)"
                }
        
                # Prompt user to select two files
                $firstFileIndex = Read-Host "Enter the number corresponding to the first file"
                $secondFileIndex = Read-Host "Enter the number corresponding to the second file"
        
                # Validate selection
                if (-not [int]$firstFileIndex -or -not [int]$secondFileIndex -or
                    $firstFileIndex -le 0 -or $secondFileIndex -le 0 -or
                    $firstFileIndex -gt $files.Count -or $secondFileIndex -gt $files.Count) {
                    Write-Host "Invalid selection. Please try again." -ForegroundColor Red
                    Continue
                }
        
                # Get the selected files
                $firstFile = $files[[int]$firstFileIndex - 1]
                $secondFile = $files[[int]$secondFileIndex - 1]
        
                # Calculate and compare hashes for MD5, SHA1, and SHA256
                Write-Host "`nComparing the following files:" -ForegroundColor Cyan
                Write-Host "1. $($firstFile.FullName)" -ForegroundColor Yellow
                Write-Host "2. $($secondFile.FullName)" -ForegroundColor Yellow
        
                $hashAlgorithms = @("MD5", "SHA1", "SHA256")
                foreach ($algorithm in $hashAlgorithms) {
                    $firstHash = (Get-FileHash -Path $firstFile.FullName -Algorithm $algorithm).Hash
                    $secondHash = (Get-FileHash -Path $secondFile.FullName -Algorithm $algorithm).Hash
        
                    if ($firstHash -eq $secondHash) {
                        Write-Host "${algorithm}: Hashes are identical." -ForegroundColor Green
                    }
                    else {
                        Write-Host "${algorithm}: Hashes are different." -ForegroundColor Red
                        Write-Host "First File: $firstHash" -ForegroundColor Cyan
                        Write-Host "Second File: $secondHash" -ForegroundColor Cyan
                    }
                }
            }
            catch {
                Write-Host "An error occurred while comparing file hashes: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        q {
            Write-Host "Exiting the program. Goodbye!" -ForegroundColor Cyan
            break
        }
        Default {
            Write-Host "Invalid selection! Please try again."
        }
    } # Closing brace for Switch statement
} While ($user_input -ne 'q')  # Loop continues unless 'q' (Exit) is selected
