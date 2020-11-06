# VBoxCloak

A PowerShell script that attempts to help malware analysts hide their Windows VirtualBox Windows VM's from malware that may be trying to evade analysis. Guaranteed to bring down your pafish ratings by at least a few points ;)

The script accomplishes this by doing the following:

- Renames several registry keys that malware typically uses for VM detection.
- Kills VirtualBox processes (VBoxService and VBoxTray).
- Deletes VirtualBox driver files (this will not crash VirtualBox, since these drivers are loaded into memory anyway!

Tested on Windows 7 VM - probably works on Windows 10 and XP as well.

# Warnings

- Ensure to make a snapshot of your VM before running this.

# Usage

1. Simply run VBoxCloak.ps1 as Administrator on your Windows VirtualBox VM.
2. Detonate your malware. Profit.
3. When done, reset your VM to clean state.


