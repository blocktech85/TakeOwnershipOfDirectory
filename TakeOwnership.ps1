Clear-Host

$equals115 = "=" * 150
Write-Host $equals115 -ForegroundColor White
Write-Host "================================================== Program To Take Ownership Of Directories/Files ====================================================" -ForegroundColor White
Write-Host $equals115 -ForegroundColor White
Write-Host ""

$pshost = Get-Host
$pswindow = $pshost.UI.RawUI

# Increase buffer size width first, so it's not smaller than the window
$newBufferSize = $pswindow.BufferSize
$newBufferSize.Width = 150
$pswindow.BufferSize = $newBufferSize

# Then set window size width to desired value
$newWindowSize = $pswindow.WindowSize
$newWindowSize.Width = 150
$pswindow.WindowSize = $newWindowSize


$asciiArt = @'                                                                                                                        
          ____                                             ___       ___                                                   ___       
         6MMMMb/                                           `MM       `MM                                                   `MM       
        8P    YM                                     /      MM        MM                             /                      MM       
       6M      Y ___  __   _____  ____    _    ___  /M      MM  __    MM   __   ____  ____    ___   /M      ____     ____   MM  __   
       MM        `MM 6MM  6MMMMMb `MM(   ,M.   )M' /MMMMM   MM 6MMb   MM   d'  6MMMMb `MM(    )M'  /MMMMM  6MMMMb   6MMMMb. MM 6MMb  
       MM         MM69 " 6M'   `Mb `Mb   dMb   d'   MM      MMM9 `Mb  MM  d'  6M'  `Mb `Mb    d'    MM    6M'  `Mb 6M'   Mb MMM9 `Mb 
       MM     ___ MM'    MM     MM  YM. ,PYM. ,P    MM      MM'   MM  MM d'   MM    MM  YM.  ,P     MM    MM    MM MM    `' MM'   MM 
       MM     `M' MM     MM     MM  `Mb d'`Mb d'    MM      MM    MM  MMdM.   MMMMMMMM   MM  M      MM    MMMMMMMM MM       MM    MM 
       YM      M  MM     MM     MM   YM,P  YM,P     MM      MM    MM  MMPYM.  MM         `Mbd'      MM    MM       MM       MM    MM 
        8b    d9  MM     YM.   ,M9   `MM'  `MM'     YM.  ,  MM    MM  MM  YM. YM    d9    YMP   68b YM.  ,YM    d9 YM.   d9 MM    MM 
         YMMMM9  _MM_     YMMMMM9     YP    YP       YMMM9 _MM_  _MM__MM_  YM._YMMMM9      M    Y89  YMMM9 YMMMM9   YMMMM9 _MM_  _MM_
                                                                                          d'                                         
                                                                                      (8),P                                          
                                                                                       YMM                                           

'@

Write-Host $asciiArt -ForegroundColor Cyan
Write-Host ""

class Logger {
    [string]$LogFile
    Logger([string]$path) { $this.LogFile = $path }
    [void] Write([string]$msg) {
        $timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        $line = "$timestamp - $msg"
        Write-Host $msg
        Add-Content -Path $this.LogFile -Value $line
    }
    [void] WriteError([string]$msg) {
        $timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        $line = "$timestamp - ERROR: $msg"
        Write-Error $msg
        Add-Content -Path $this.LogFile -Value $line
    }
}

class ACLManager {
    [string]$TargetPath
    [string]$BackupDir
    [string]$BackupFormat
    [Logger]$Logger
    [string]$CurrentUser
    [int]$MaxRetries = 3
    [int]$RetryDelay = 5

    # Added properties to store backup file paths for access outside method
    [string]$LastAclBackupPath
    [string]$LastSddlBackupPath

    ACLManager([string]$target, [string]$backupDir, [string]$format, [Logger]$logger) {
        $this.TargetPath = $target
        $this.BackupDir = $backupDir
        $this.BackupFormat = $format
        $this.Logger = $logger
        $this.CurrentUser = "$env:USERDOMAIN\$env:USERNAME"
    }
    [bool] UserHasFullControl([string]$path) {
        try {
            $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
            foreach ($rule in $acl.Access) {
                if (($rule.IdentityReference -eq $this.CurrentUser) -and
                    (($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne 0)) {
                    return $true
                }
            }
        } catch {
            $this.Logger.WriteError("Error getting ACL: $_")
        }
        return $false
    }
    [void] BackupACLs() {
        $this.Logger.Write("Backing up ACLs in $($this.BackupFormat) format...")
        $allItems = Get-ChildItem -LiteralPath $this.TargetPath -Recurse -Force -ErrorAction SilentlyContinue
        $items = @($this.TargetPath) + ($allItems | ForEach-Object { $_.FullName })
        $count = 0
        $total = $items.Count
        if ($total -eq 0) { $total = 1 }
        $aclObjects = New-Object System.Collections.Generic.List[object]
        foreach ($item in $items) {
            $count++
            Write-Progress -Activity "Backing up ACLs" -Status ("Processing item {0} of {1}" -f $count, $total) -PercentComplete ([math]::Round(($count / $total) * 100))
            try {
                $acl = Get-Acl -LiteralPath $item -ErrorAction SilentlyContinue
                if ($acl) {
                    $obj = [PSCustomObject]@{
                        Path = $item
                        Sddl = $acl.Sddl
                    }
                    $aclObjects.Add($obj)
                }
            } catch {
                $errorMessage = $_.Exception.Message
                $this.Logger.WriteError("Failed ACL read on ${item}: ${errorMessage}")
            }
        }
        Write-Progress -Activity "Backing up ACLs" -Completed
        $timestamp = (Get-Date -Format "yyyyMMdd_HHmmss")
        $pathBase = Join-Path $this.BackupDir "ACLbackup_$timestamp"
        if ($this.BackupFormat -eq "JSON") {
            $this.LastAclBackupPath = "$pathBase.json"
            $aclObjects | ConvertTo-Json -Depth 10 | Out-File -FilePath $this.LastAclBackupPath -Encoding UTF8
            $this.Logger.Write("ACL Backup saved as JSON at $($this.LastAclBackupPath)")
        } else {
            $this.LastAclBackupPath = "$pathBase.xml"
            $aclObjects | Export-Clixml -Path $this.LastAclBackupPath
            $this.Logger.Write("ACL Backup saved as XML at $($this.LastAclBackupPath)")
        }
        try {
            $rootAcl = Get-Acl -LiteralPath $this.TargetPath
            $this.LastSddlBackupPath = Join-Path $this.BackupDir ("SDDLbackup_$timestamp.txt")
            $rootAcl.Sddl | Out-File -FilePath $this.LastSddlBackupPath -Encoding UTF8
            $this.Logger.Write("Root SDDL backup saved at $($this.LastSddlBackupPath)")
        } catch {
            $errorMessage = $_.Exception.Message
            $this.Logger.WriteError("Failed to backup SDDL: ${errorMessage}")
        }
    }
    [bool] TakeOwnershipFallbackParent([string]$item) {
        try {
            $parent = Split-Path $item -Parent
            if ([string]::IsNullOrEmpty($parent) -or -not (Test-Path $parent)) {
                $this.Logger.WriteError("No valid parent path for fallback")
                return $false
            }
            $this.Logger.Write("Taking ownership of parent ${parent} as fallback")
            echo Y | takeown.exe /F $parent /A /R /D Y | ForEach-Object { $this.Logger.Write($_) }
            return $true
        } catch {
            $errorMessage = $_.Exception.Message
            $this.Logger.WriteError("Fallback failed: ${errorMessage}")
            return $false
        }
    }
    [bool] TakeOwnershipAsSystem([string]$cmd) {
        $taskName = "TakeOwnershipSys_" + ([guid]::NewGuid())
        $exe = (Get-Command powershell).Source
        $scriptArg = "-NoProfile -WindowStyle Hidden -Command `"& { $cmd }`""
        try {
            $this.Logger.Write("Creating SYSTEM scheduled task for ownership...")
            $action = New-ScheduledTaskAction -Execute $exe -Argument $scriptArg
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
            $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings
            Register-ScheduledTask -TaskName $taskName -InputObject $task | Out-Null
            Start-ScheduledTask -TaskName $taskName
            Start-Sleep -Seconds 10
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            $this.Logger.Write("SYSTEM scheduled task finished.")
            return $true
        } catch {
            $errorMessage = $_.Exception.Message
            $this.Logger.WriteError("SYSTEM task failed: ${errorMessage}")
            return $false
        }
    }
    [PSCustomObject] ChangeOwnershipWithRetries() {
        $this.Logger.Write("Starting ownership & permission changes on $($this.TargetPath)...")
        $this.BackupACLs()
        $items = Get-ChildItem -LiteralPath $this.TargetPath -Recurse -Force -ErrorAction SilentlyContinue
        $allEntries = @($this.TargetPath) + $items.FullName
        $total = $allEntries.Count
        if ($total -eq 0) { $total = 1 }
        $count = 0
        $success = 0
        $failures = New-Object System.Collections.Generic.List[string]
        foreach ($entry in $allEntries) {
            $count++
            Write-Progress -Activity "Ownership & Permissions" `
                -Status ("Processing {0} of {1}" -f $count, $total) `
                -PercentComplete ([math]::Round(($count / $total)*100))
            $retry = 0
            $skip = $false
            $owned = $false
            do {
                try {
                    $this.Logger.Write("Processing ${entry} (Attempt $($retry+1))")
                    if ((Test-Path $entry) -and (Get-Item $entry).PsIsContainer -and -not $owned) {
                        echo Y | takeown.exe /F $entry /A /R /D Y | ForEach-Object { $this.Logger.Write($_) }
                        $owned = $true
                    }
                    $acl = Get-Acl -LiteralPath $entry
                    $acl.SetOwner([System.Security.Principal.NTAccount] $this.CurrentUser)
                    $acl.SetAccessRuleProtection($false, $true)
                    Set-Acl -LiteralPath $entry -AclObject $acl
                    $this.Logger.Write("Owner set; inheritance enabled on ${entry}")
                    $icaclsArg = "$($this.CurrentUser):(OI)(CI)F"
                    echo Y | icacls $entry /grant $icaclsArg /T /C 2>&1 | ForEach-Object { $this.Logger.Write($_) }
                    $success++
                    break
                } catch {
                    $errMsg = $_.Exception.Message
                    $this.Logger.WriteError("Error with ${entry}: ${errMsg}")
                    if ($retry -eq 0 -and $this.TakeOwnershipFallbackParent($entry)) {
                        $this.Logger.Write("Parent fallback succeeded, retrying...")
                        $retry++
                        Start-Sleep -Seconds $this.RetryDelay
                        continue
                    }
                    if ($retry -eq 1) {
                        $cmd = "echo Y | takeown.exe /F `"$entry`" /A /R /D Y"
                        if ($this.TakeOwnershipAsSystem($cmd)) {
                            $this.Logger.Write("SYSTEM fallback succeeded on ${entry}")
                            $retry++
                            Start-Sleep -Seconds $this.RetryDelay
                            continue
                        }
                    }
                    if ($errMsg -match 'access is denied' -and $retry -lt $this.MaxRetries) {
                        $this.Logger.Write("Access denied, retrying in $($this.RetryDelay)s...")
                        $retry++
                        Start-Sleep -Seconds $this.RetryDelay
                    } else {
                        $this.Logger.WriteError("Max retries or other error, skipping ${entry}")
                        $failures.Add($entry)
                        $skip = $true
                    }
                }
            } while (-not $skip -and $retry -lt $this.MaxRetries)
        }
        Write-Progress -Activity "Ownership & Permissions" -Completed
        return [PSCustomObject]@{
            TotalItems = $total
            SuccessCount = $success
            FailedItems = $failures
        }
    }
}

function Get-ValidatedPath([string]$prompt, [string]$default) {
    do {
        $input = Read-Host $prompt
        if ([string]::IsNullOrWhiteSpace($input)) { $input = $default }
        $inputTrimmed = $input.Trim()
        if (Test-Path -Path $inputTrimmed) {
            return $inputTrimmed
        } else {
            Write-Host "Invalid or inaccessible path: '$inputTrimmed'. Please enter a valid existing path." -ForegroundColor Yellow
            Write-Host "Debug info: Test-Path -Path returns: $(Test-Path -Path $inputTrimmed)" -ForegroundColor DarkGray
        }
    } while ($true)
}

function Get-BackupFormat() {
    $msg = @"
	
Select ACL backup format:
  1) JSON (default)
  2) XML (Export-Clixml)

Enter 1 or 2 (default 1)
"@
    do {
        $choice = Read-Host $msg
        if ([string]::IsNullOrWhiteSpace($choice) -or $choice -notin '1','2') { $choice = '1' }
        if ($choice -eq '2') { return 'XML' } else { return 'JSON' }
    } while ($false)
}

$defaultTarget = "$env:SystemDrive\"
$targetPath = Get-ValidatedPath "Enter target file or folder path (default: $defaultTarget)" $defaultTarget

$defaultBackup = "$env:SystemDrive\ACLBackups"
if (!(Test-Path $defaultBackup)) {
    New-Item -ItemType Directory -Path $defaultBackup -Force | Out-Null
}
$backupDir = Get-ValidatedPath "Enter ACL backup directory (default: $defaultBackup)" $defaultBackup

$backupFormat = Get-BackupFormat

$logPath = Join-Path $backupDir ("TakeOwnership_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")
$logger = [Logger]::new($logPath)
$logger.Write("Initialized logging at $logPath")

$aclManager = [ACLManager]::new($targetPath, $backupDir, $backupFormat, $logger)

$result = $aclManager.ChangeOwnershipWithRetries()

Clear-host
Write-Host $equals115 -ForegroundColor Green
Write-Host "===============================================================" -ForegroundColor Green -NoNewline
Write-Host " OPERATIONAL SUMMARY " -ForegroundColor Blue -NoNewline
Write-Host "==================================================================" -ForegroundColor Green

Write-Host $equals115 -ForegroundColor Green
Write-Host ""

Write-Host "Path processed: " -ForegroundColor White -NoNewline
Write-Host "$targetPath" -ForegroundColor Blue

Write-Host ""
Write-Host "Total items in path processed: " -ForegroundColor White -NoNewline
Write-Host "$($result.TotalItems)" -ForegroundColor Blue

Write-Host ""
Write-Host "Root ACL Backup saved at: " -ForegroundColor White -NoNewline
Write-Host "$($aclManager.LastAclBackupPath)" -ForegroundColor Blue

Write-Host ""
Write-Host "Root SDDL Backup saved at: " -ForegroundColor White -NoNewline
Write-Host "$($aclManager.LastSddlBackupPath)" -ForegroundColor Blue

Write-Host ""
Write-Host "Log file: " -ForegroundColor White -NoNewline
Write-Host "$logPath" -ForegroundColor Blue

Write-Host ""
Write-Host ""
Write-Host ""
Write-Host "Successfully took ownership on $($result.SuccessCount) of $($result.TotalItems) items." -ForegroundColor Cyan

if ($result.FailedItems.Count -gt 0) {
    Write-Host ""
    Write-Host ""
    Write-Host "Failed on these items:" -ForegroundColor Red
    $result.FailedItems | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
} else {
    Write-Host ""
    Write-Host ""
    Write-Host "                                                       ** You Have Ownership of All Files! **" -ForegroundColor Blue
    Write-Host ""
}

Write-Host $equals115 -ForegroundColor Green
Write-Host $equals115 -ForegroundColor Green
Write-Host ""
Write-Host ""
Write-Host ""

