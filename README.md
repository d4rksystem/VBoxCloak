# VBoxCloak

A PowerShell script that attempts to help malware analysts hide their VirtualBox Windows VM's from malware that may be trying to evade analysis. Guaranteed to bring down your pafish ratings by at least a few points ;)

The script accomplishes this by doing the following:

- Renames several registry keys that malware typically uses for VM detection.
- Kills VirtualBox processes (VBoxService and VBoxTray, etc.).
- Deletes VirtualBox driver files (this will not crash VirtualBox, since these drivers are loaded into memory anyway!).
- Deletes or renames VirtualBox supporting files in System32 and SysWOW64 directories.

For more info, see my blog post here: 
https://securityliterate.com/hiding-virtual-machines-from-malware-introducing-vmwarecloak-vboxcloak/

Note: This script will not cover ALL VM detection techniques! There are a lot of ways to detect a VM, and many of these cannot be fixed with a simple Powershell script. For example, techniques such as RDTSC and timing detection are not covered, neither is CPUID detection.

Tested on Windows 7 and Windows 10 - Probably works on Windows XP and Windows 11 as well.

Spot any bugs? Let me know!

# Usage

1. Simply run VBoxCloak.ps1 as Administrator on your Windows VirtualBox VM.
2. Detonate your malware. Profit.
3. When done, reset your VM to clean state.

Usage examples:

Make registry changes, remove VBox files, and kill VBox processes:
  
  - "VBoxCloak.ps1 -all"
  
Just make registry modificaitons:
  
  - "VBoxCloak.ps1 -reg"
  
Just remove VBox files:
  
  - "VBoxCloak.ps1 -files"
  
Just kill VBox processes:
  
  - "VBoxCloak.ps1 -procs"

# Warnings & Disclaimers

- This code is in Beta. I know I could have coded it better, but sometimes quick and dirty is best.
- Use at your own risk! Use only in a VM, and NOT on your host.
- Ensure to make a snapshot of your VM before running this.
- Using the "files" and/or "procs" command line arguments may result in lower VM performance. This is because this script removes several files that are required for supporting functions such as graphics, keyboard input, etc. Just revert VM to clean state if this messes anything up.

