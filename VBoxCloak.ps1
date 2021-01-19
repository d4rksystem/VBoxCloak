#################################################
## VBoxCloak.ps1: A script that attempts to hide the VirtualBox hypervisor from malware by modifying registry keys, killing associated processes, and removing uneeded driver/system files.
## Written and tested on Windows 7 System, but will likely work for Windows 10 as well.
## Many thanks to pafish for some of the ideas :) - https://github.com/a0rtega/pafish
##################################################
## Author: d4rksystem
## Version: 0.4
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
Write-Output 'VBoxCloak.ps1 by @d4rksystem (Kyle Cucci)'
Write-Output 'Usage: VBoxCloak.ps1 -<option>'
Write-Output 'Example Usage: VBoxCloak.ps1 -all'
Write-Output 'Options:'
Write-Output 'all: Enable all options.'
Write-Output 'reg: Make registry changes.'
Write-Output 'procs: Kill processes.'
Write-Output 'files: Make file system changes.'
Write-Output 'Make sure to run as Admin!'
Write-Output '*****************************************'

# Define random string generator function
function Get-RandomString {

    $charSet = "abcdefghijklmnopqrstuvwxyz0123456789".ToCharArray()
    
    for ($i = 0; $i -lt 10; $i++ ) {
        $randomString += $charSet | Get-Random
    }

    return $randomString
}

# Stop VBox Processes
if ($procs) {

    Write-Output '[*] Attempting to kill VirtualBox processes (VBoxTray / VBoxService)...'

    $VBoxTray = Get-Process "VBoxTray" -ErrorAction SilentlyContinue

    if ($VBoxTray) {
        $VBoxTray | Stop-Process -Force
        Write-Output '[*] VBoxTray process killed!'
    }

    if (!$VBoxTray) {
	    Write-Output '[!] VBoxTray process does not exist!'
    }

    $VBoxService = Get-Process "VBoxService" -ErrorAction SilentlyContinue

    if ($VBoxService) {
        $VBoxService | Stop-Process -Force
        Write-Output '[*] VBoxService process killed!'
    }

    if (!$VBoxService) {
	    Write-Output '[!] VBoxService process does not exist!'
    }
}

# Modify VBox registry keys
if ($reg) {

    # Modify system BIOS version

    if (Get-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "SystemBiosVersion" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Modifying Reg Key HKLM:\HARDWARE\Description\System\SystemBiosVersion..."
	    Set-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "SystemBiosVersion" -Value $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\HARDWARE\Description\System\SystemBiosVersion does not seem to exist! Skipping this one...'
    }

    # Modify CurrentControlSet BIOS info

    if (Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Modifying Reg Key Values in HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation..."
	    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "BIOSVersion" -Value $(Get-RandomString)
	    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "BIOSReleaseDate" -Value $(Get-RandomString)
	    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "BIOSProductName" -Value $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation does not seem to exist! Skipping this one...'
    }

    # Modify system BIOS date

    if (Get-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "SystemBiosDate" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Modifying Reg Key HKLM:\HARDWARE\Description\System\SystemBiosDate"
	    Set-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "SystemBiosDate" -Value $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\HARDWARE\Description\System\SystemBiosDate does not seem to exist! Skipping this one...'
    }

    # Modify system BIOS Video Version

    if (Get-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "VideoBiosVersion" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Modifying Reg Key HKLM:\HARDWARE\Description\System\VideoBiosVersion"
	    Set-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "VideoBiosVersion" -Value $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\HARDWARE\Description\System\VideoBiosVersion does not seem to exist! Skipping this one...'
    }

    # Rename Guest Additions Reg Key

    if (Get-Item -Path "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions"
	    Rename-Item -Path "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions" -NewName $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions does not seem to exist, or has already been renamed! Skipping this one...'
    }

    # Rename ACPI DSDT Reg Key

    if (Get-Item -Path "HKLM:\HARDWARE\ACPI\DSDT\VBOX__" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\HARDWARE\ACPI\DSDT\VBOX__"
	    Rename-Item -Path "HKLM:\HARDWARE\ACPI\DSDT\VBOX__" -NewName $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\HARDWARE\ACPI\DSDT\VBOX__ does not seem to exist, or has already been renamed! Skipping this one...'
    }

    # Rename ACPI FADT Reg Key

    if (Get-Item -Path "HKLM:\HARDWARE\ACPI\FADT\VBOX__" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\HARDWARE\ACPI\FADT\VBOX__"
	    Rename-Item -Path "HKLM:\HARDWARE\ACPI\FADT\VBOX__" -NewName $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\HARDWARE\ACPI\FADT\VBOX__ does not seem to exist, or has already been renamed! Skipping this one...'
    }

    # Rename ACPI RSDT Reg Key

    if (Get-Item -Path "HKLM:\HARDWARE\ACPI\RSDT\VBOX__" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\HARDWARE\ACPI\RSDT\VBOX__"
	    Rename-Item -Path "HKLM:\HARDWARE\ACPI\RSDT\VBOX__" -NewName $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\HARDWARE\ACPI\RSDT\VBOX__ does not seem to exist, or has already been renamed! Skipping this one...'
    }

    # Rename VBoxMouse Reg Key

    if (Get-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxMouse" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxMouse"
	    Rename-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxMouse" -NewName $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxMouse does not seem to exist, or has already been renamed! Skipping this one...'
    }

    # Rename VBoxService Reg Key

    if (Get-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxService" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxService"
	    Rename-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxService" -NewName $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxService does not seem to exist, or has already been renamed! Skipping this one...'
    }

    # Rename VBoxSF Reg Key

    if (Get-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxSF" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxSF"
	    Write-Output "[!] Warning: This will disconnect VM shared folders. You will need to reconnect them later..."
	    Rename-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxSF" -NewName $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxSF does not seem to exist, or has already been renamed! Skipping this one...'
    }

    # Rename VBoxVideo Reg Key

    if (Get-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxVideo" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxVideo"
	    Rename-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxVideo" -NewName $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxVideo does not seem to exist, or has already been renamed! Skipping this one...'
    }

    # Rename VBoxGuest Reg Key

    if (Get-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxGuest" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxGuest"
	    Rename-Item -Path "HKLM:\SYSTEM\ControlSet001\services\VBoxGuest" -NewName $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\SYSTEM\ControlSet001\services\VBoxGuest does not seem to exist, or has already been renamed! Skipping this one...'
    }

    # Rename VBoxTray Reg Key

    if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "VBoxTray" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\VBoxTray"
	    Rename-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "VBoxTray" -NewName $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\VBoxTray does not seem to exist, or has already been renamed! Skipping this one...'
    }

    # Rename VBox Uninstaller Reg Key

    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Oracle VM VirtualBox Guest Additions" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Oracle VM VirtualBox Guest Additions"
	    Rename-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Oracle VM VirtualBox Guest Additions" -NewName $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Oracle VM VirtualBox Guest Additions does not seem to exist, or has already been renamed! Skipping this one...'
    }
}

# Remove VBox Driver Files
if ($files) {

    Write-Output '[*] Attempting to remove VirtualBox driver files...'

    $vboxFiles1 = "C:\Windows\System32\drivers\VBox*"

    if ($vboxFiles1) {
        Remove-Item $vboxFiles1
    }

    # Remove VBox system32 files

    Write-Output '[*] Attempting to remove VirtualBox system32 files...'

    $vboxFiles2 = "C:\Windows\System32\VBox*"
    Remove-Item $vboxFiles2 -EV Err -ErrorAction SilentlyContinue

    # Rename VBoxMRXNP DLL file
    # We have to rename this file because we get errors when attempting to delete it! :o

    Write-Output '[*] Attempting to rename VBoxMRXNP.dll file...'
    Rename-Item "C:\Windows\System32\VBoxMRXNP.dll" "C:\Windows\System32\$(Get-RandomString).dll"

    # Rename VirtualBox folder path

    Write-Output '[*] Attempting to rename VirtualBox folder path...'
    Rename-Item "C:\Program Files\Oracle\VirtualBox Guest Additions" "C:\Program Files\Oracle\$(Get-RandomString)"
}

Write-Output '** Done! Did you recieve a lot of errors? Try running as Admin!'
