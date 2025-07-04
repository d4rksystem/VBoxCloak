#################################################
## VBoxCloak.ps1: A script that attempts to hide the VirtualBox hypervisor from malware by modifying registry keys, killing associated processes, and removing uneeded driver/system files.
## Written and tested on Windows 7 and Windows 10. Should work for Windows 11 as well!
## Many thanks to pafish for some of the ideas - https://github.com/a0rtega/pafish
##################################################
## Author: d4rksystem (Kyle Cucci)
## Version: 0.7 (July 2025)
##################################################

# Define command line parameters
param (
    [switch]$all = $false,
    [switch]$reg = $false,
    [switch]$procs = $false,
    [switch]$files = $false
)

if ($all) {
    $reg = $true
    $procs = $true
    $files = $true
}

# Menu / Helper stuff
Write-Output "VBoxCloak.ps1 by @d4rksystem (Kyle Cucci)"
Write-Output "Usage: VBoxCloak.ps1 -<option>"
Write-Output "Example Usage: VBoxCloak.ps1 -all"
Write-Output "Options:"
Write-Output "all: Enable all options."
Write-Output "reg: Make registry changes."
Write-Output "procs: Kill processes."
Write-Output "files: Make file system changes."
Write-Output "`nTips: Run as Admin or you will get a lot of errors!"
Write-Output "Warning: Only run in a virtual machine!"
Write-Output "Warning: This script will likely temporarily break some functions like snapshots."
Write-Output "*****************************************"

# -------------------------------------------------------------------------------------------------------
# Define random string generator function

function Get-RandomString {

    $charSet = "abcdefghijklmnopqrstuvwxyz0123456789".ToCharArray()
    
    for ($i = 0; $i -lt 10; $i++ ) {
        $randomString += $charSet | Get-Random
    }

    return $randomString
}

# -------------------------------------------------------------------------------------------------------
# Stop VBox Processes

$process_list = "VBoxTray", "VBoxService", "VBoxControl"

if ($procs) {

    Write-Output "`n[*] Attempting to kill VMware processes..."

    foreach ($p in $process_list) {

        $process = Get-Process "$p" -ErrorAction SilentlyContinue

        if ($process) {
            $process | Stop-Process -Force
            Write-Output "[+] $p process killed!"
        }

        if (!$process) {
            Write-Output "[!] $p process does not exist!"
        }
     }        
}

# -------------------------------------------------------------------------------------------------------
# Modify VBox registry keys - Refactored with loops

if ($reg) {

    # Registry properties to modify (Set-ItemProperty)
    $propertiesToModify = @(
        @{ Path = "HKLM:\HARDWARE\Description\System"; Name = "SystemBiosVersion" },
        @{ Path = "HKLM:\HARDWARE\Description\System"; Name = "SystemBiosDate" },
        @{ Path = "HKLM:\HARDWARE\Description\System"; Name = "VideoBiosVersion" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation"; Name = "BIOSVersion" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation"; Name = "BIOSReleaseDate" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation"; Name = "BIOSProductName" },
        @{ Path = "HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0"; Name = "Identifier" }
    )

    # Registry keys to rename (Rename-Item)
    $keysToRename = @(
        @{ Path = "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions" },
        @{ Path = "HKLM:\HARDWARE\ACPI\DSDT\VBOX__" },
        @{ Path = "HKLM:\HARDWARE\ACPI\FADT\VBOX__" },
        @{ Path = "HKLM:\HARDWARE\ACPI\RSDT\VBOX__" },
        @{ Path = "HKLM:\SYSTEM\ControlSet001\services\VBoxMouse" },
        @{ Path = "HKLM:\SYSTEM\ControlSet001\services\VBoxService" },
        @{ Path = "HKLM:\SYSTEM\ControlSet001\services\VBoxSF" },
        @{ Path = "HKLM:\SYSTEM\ControlSet001\services\VBoxVideo" },
        @{ Path = "HKLM:\SYSTEM\ControlSet001\services\VBoxGuest" },
	@{ Path = "HKLM:\SYSTEM\ControlSet001\Enum\ACPI\PNP0C0C" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Oracle VM VirtualBox Guest Additions" }
    )

    # Registry property names to rename (Rename-ItemProperty)
    $propertyNamesToRename = @(
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Name = "VBoxTray" }
    )
	
    # Process registry properties to modify
    Write-Output "`n[*] Modifying registry property values..."
    foreach ($property in $propertiesToModify) {
        if (Get-ItemProperty -Path $property.Path -Name $property.Name -ErrorAction SilentlyContinue) {
            Write-Output "[+] Modifying $($property.Path)\$($property.Name)..."
            Set-ItemProperty -Path $property.Path -Name $property.Name -Value $(Get-RandomString) -ErrorAction SilentlyContinue
        } else {
            Write-Output "[!] Property $($property.Path)\$($property.Name) does not exist! Skipping..."
        }
    }

    # Process registry keys to rename
	Write-Output "`n[*] Renaming registry keys..."
	foreach ($key in $keysToRename) {
		if (Get-Item -Path $key.Path -ErrorAction SilentlyContinue) {
			Write-Output "[+] Renaming key $($key.Path)..."
			Rename-Item -Path $key.Path -NewName $(Get-RandomString) -ErrorAction SilentlyContinue
		} 	else {
        Write-Output "[!] Key $($key.Path) does not exist or has already been renamed! Skipping..."
    }
}

    # Process registry property names to rename
    Write-Output "`n[*] Renaming registry property names..."
    foreach ($propertyName in $propertyNamesToRename) {
        if (Get-ItemProperty -Path $propertyName.Path -Name $propertyName.Name -ErrorAction SilentlyContinue) {
            Write-Output "[+] Renaming property $($propertyName.Path)\$($propertyName.Name)..."
            Rename-ItemProperty -Path $propertyName.Path -Name $propertyName.Name -NewName $(Get-RandomString) -ErrorAction SilentlyContinue
        } else {
            Write-Output "[!] Property $($propertyName.Path)\$($propertyName.Name) does not exist or has already been renamed! Skipping..."
        }
    }

    Write-Output "`n[*] Registry modifications completed."
}

# -------------------------------------------------------------------------------------------------------
# Rename VBox Files

if ($files) {
	
	# Rename driver files
	
	$file_list = "VBoxMouse.sys", "VBoxSF.sys", "VBoxWddm.sys", "VBoxGuest.sys"

	Write-Output "`n[*] Attempting to rename VirtualBox driver files..."

    foreach ($f in $file_list) {
		Write-Output "[+] Attempting to rename $f..."
		try {
			Rename-Item "C:\Windows\System32\drivers\$f" "C:\Windows\System32\drivers\$(Get-RandomString).sys" -ErrorAction Stop
		}
		catch {
			Write-Output "[!] File does not seem to exist! Skipping..."
		}
	}

	# Rename system32 executable files
	
	Write-Output "`n[*] Attempting to rename System32 VirtualBox executable files..."
	
	$file_list = "VBoxTray.exe", "VBoxControl.exe", "VBoxService.exe", "VBoxMRXNP.dll", "VBoxSVGA.dll", "VBoxHook.dll", "VBoxNine.dll", "VBoxGL.dll", "VBoxDispD3D.dll", "VBoxICD.dll"

    foreach ($f in $file_list) {
    	Write-Output "[+] Attempting to rename $f..."
		try {
			Rename-Item "C:\Windows\System32\$f" "C:\Windows\System32\$(Get-RandomString).sys" -ErrorAction Stop
		}
		catch {
			Write-Output "[!] File does not seem to exist! Skipping..."
		}
	}
	
	# Rename SysWOW64 executable files
	
	Write-Output "`n[*] Attempting to rename SysWOW64 VirtualBox executable files..."
	
	$file_list = "VBoxGL-x86.dll", "VBoxMRXNP.dll", "VBoxDispD3D-x86.dll", "VBoxICD-x86.dll", "VBoxSVGA-x86.dll", "VBoxNine-x86.dll"

    foreach ($f in $file_list) {
    	Write-Output "[+] Attempting to rename $f..."
		
		try {
			Rename-Item "C:\Windows\SysWOW64\$f" "C:\Windows\SysWOW64\$(Get-RandomString).sys" -ErrorAction Stop
		}
		
		catch {
			Write-Output "[!] File does not seem to exist! Skipping..."
		}
	}

	# Rename program directory

	Write-Output "[+] Attempting to rename VirtualBox program directory..."
	
	$vboxDir = Get-ChildItem "C:\Program Files\Oracle\VirtualBox*"
	
	# Check for existence of files.
	if ($vboxDir) {
	
		Rename-Item "C:\Program Files\Oracle\VirtualBox Guest Additions" "C:\Program Files\Oracle\$(Get-RandomString)" -ErrorAction SilentlyContinue
	}
	
	else {
		Write-Output "[!] Directory does not appear to exist! Skipping..."
	}
}

Write-Output ""
Write-Output "** Done! Did you recieve a lot of errors? You need to run as Admin!"
Write-Output "** Spot any bugs or issues? DM me on Twitter or open an issues on Github! :)"
