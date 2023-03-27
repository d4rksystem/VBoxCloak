#################################################
## VBoxCloak.ps1: A script that attempts to hide the VirtualBox hypervisor from malware by modifying registry keys, killing associated processes, and removing uneeded driver/system files.
## Written and tested on Windows 7 and Windows 10. Should work for Windows 11 as well!
## Many thanks to pafish for some of the ideas - https://github.com/a0rtega/pafish
##################################################
## Author: d4rksystem (Kyle Cucci)
## Version: 0.6
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
Write-Output "Tips: Run as Admin or you will get a lot of errors!"
Write-Output "Warning: Only run in a virtual machine!"
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

    Write-Output "[*] Attempting to kill VMware processes..."

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
# Modify VBox registry keys

if ($reg) {

    # Modify system BIOS version

    if (Get-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "SystemBiosVersion" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Modifying Reg Key HKLM:\HARDWARE\Description\System\SystemBiosVersion..."
	    Set-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "SystemBiosVersion" -Value $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\HARDWARE\Description\System\SystemBiosVersion does not seem to exist! Skipping this one..."
    }

    # Modify CurrentControlSet BIOS info

    if (Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Modifying Reg Key Values in HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation..."
	    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "BIOSVersion" -Value $(Get-RandomString)
	    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "BIOSReleaseDate" -Value $(Get-RandomString)
	    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "BIOSProductName" -Value $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation does not seem to exist! Skipping this one..."
    }

    # Modify system BIOS date

    if (Get-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "SystemBiosDate" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Modifying Reg Key HKLM:\HARDWARE\Description\System\SystemBiosDate"
	    Set-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "SystemBiosDate" -Value $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\HARDWARE\Description\System\SystemBiosDate does not seem to exist! Skipping this one..."
    }

    # Modify system BIOS Video Version

    if (Get-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "VideoBiosVersion" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Modifying Reg Key HKLM:\HARDWARE\Description\System\VideoBiosVersion"
	    Set-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "VideoBiosVersion" -Value $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\HARDWARE\Description\System\VideoBiosVersion does not seem to exist! Skipping this one..."
    }

    # Rename Guest Additions Reg Key

    if (Get-Item -Path "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions"
	    Rename-Item -Path "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions does not seem to exist, or has already been renamed! Skipping this one..."
    }

    # Rename ACPI DSDT Reg Key

    if (Get-Item -Path "HKLM:\HARDWARE\ACPI\DSDT\VBOX__" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\HARDWARE\ACPI\DSDT\VBOX__"
	    Rename-Item -Path "HKLM:\HARDWARE\ACPI\DSDT\VBOX__" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\HARDWARE\ACPI\DSDT\VBOX__ does not seem to exist, or has already been renamed! Skipping this one..."
    }

    # Rename ACPI FADT Reg Key

    if (Get-Item -Path "HKLM:\HARDWARE\ACPI\FADT\VBOX__" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\HARDWARE\ACPI\FADT\VBOX__"
	    Rename-Item -Path "HKLM:\HARDWARE\ACPI\FADT\VBOX__" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\HARDWARE\ACPI\FADT\VBOX__ does not seem to exist, or has already been renamed! Skipping this one..."
    }

    # Rename ACPI RSDT Reg Key

    if (Get-Item -Path "HKLM:\HARDWARE\ACPI\RSDT\VBOX__" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\HARDWARE\ACPI\RSDT\VBOX__"
	    Rename-Item -Path "HKLM:\HARDWARE\ACPI\RSDT\VBOX__" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\HARDWARE\ACPI\RSDT\VBOX__ does not seem to exist, or has already been renamed! Skipping this one..."
    }

    # Rename VBoxMouse Reg Key

    if (Get-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxMouse" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxMouse"
	    Rename-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxMouse" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxMouse does not seem to exist, or has already been renamed! Skipping this one..."
    }

    # Rename VBoxService Reg Key

    if (Get-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxService" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxService"
	    Rename-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxService" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxService does not seem to exist, or has already been renamed! Skipping this one..."
    }

    # Rename VBoxSF Reg Key

    if (Get-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxSF" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxSF"
	    Write-Output "[!] Warning: This will disconnect VM shared folders. You will need to reconnect them later..."
	    Rename-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxSF" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxSF does not seem to exist, or has already been renamed! Skipping this one..."
    }

    # Rename VBoxVideo Reg Key

    if (Get-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxVideo" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxVideo"
	    Rename-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxVideo" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxVideo does not seem to exist, or has already been renamed! Skipping this one..."
    }

    # Rename VBoxGuest Reg Key

    if (Get-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxGuest" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxGuest"
	    Rename-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxGuest" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxGuest does not seem to exist, or has already been renamed! Skipping this one..."
    }

    # Rename VBoxTray Reg Key

    if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "VBoxTray" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\VBoxTray"
	    Rename-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "VBoxTray" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\VBoxTray does not seem to exist, or has already been renamed! Skipping this one..."
    }

    # Rename VBox Uninstaller Reg Key

    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Oracle VM VirtualBox Guest Additions" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Oracle VM VirtualBox Guest Additions"
	    Rename-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Oracle VM VirtualBox Guest Additions" -NewName $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Oracle VM VirtualBox Guest Additions does not seem to exist, or has already been renamed! Skipping this one..."
    }
	
	# Rename VBox logical unit ID

    if (Get-ItemProperty "HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0" -Name "Identifier" -ErrorAction SilentlyContinue) {

        Write-Output "[+] Renaming Reg Key HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0"
	    Set-ItemProperty "HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0" -Name "Identifier"  -Value $(Get-RandomString)

    } Else {

        Write-Output "[!] Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Oracle VM VirtualBox Guest Additions does not seem to exist, or has already been renamed! Skipping this one..."
    }
}

# -------------------------------------------------------------------------------------------------------
# Rename VBox Files

if ($files) {
	
	# Rename driver files
	
	$file_list = "VBoxMouse.sys", "VBoxSF.sys", "VBoxWddm.sys", "VBoxGuest.sys"

	Write-Output "[*] Attempting to rename VirtualBox driver files..."

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
	
	Write-Output "[*] Attempting to rename System32 VirtualBox executable files..."
	
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
	
	Write-Output "[*] Attempting to rename SysWOW64 VirtualBox executable files..."
	
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

