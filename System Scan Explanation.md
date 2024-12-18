# System Scan Explanation
## PDF
```python
class PDF(FPDF):
        self.cell(0, 10, f"Page: {self.page_no()}", ln=1, align='C') #  print the current page number at the bottom of each page

pdf = PDF('P', 'mm', 'letter') # portrait , millimeter, Letter size
pdf.set_auto_page_break(auto=True, margin=15) # automatic page breaks when the content overflows the page
pdf.add_page() #new page to the PDF
res=''
def write_pdf(head, content):
    global res
    pdf.set_font('times', 'B', 18)
    pdf.cell(0, 10, head, ln=1) # add single line 
    pdf.set_font('times', '', 16)
    icontent = "\n".join(f"    {line}" for line in content.splitlines()) # for making it appear as a block of text under the heading
    pdf.multi_cell(0, 10, icontent) # add multiple lines
    res+=f"\n{head}:\n{content}\n"
```
## get_full_os_info
```python
 os_info = f"System: {platform.system()}\n" 
    os_info += f"Host Name: {platform.node()}\n"  
    os_info += f"Release: {platform.release()}\n" 
    os_info += f"Version: {platform.version()}\n"  
    os_info += f"Machine: {platform.machine()}\n"  
    os_info += f"Processor: {platform.processor()}\n"   
    os_info += f"Python Version: {platform.python_version()}\n"
    return [os_info]
```
Getting basic os info

## get_dotnet_version
```python
def get_dotnet_version():
    w = wmi.WMI()
    dotnet_versions = []
    registry_query = "SELECT * FROM StdRegProv"
    reg = w.query(registry_query)
    for reg_obj in reg:
        if "Software\\Microsoft\\NET Framework Setup\\NDP" in reg_obj: # check if .NET is available in registry
            version = reg_obj["Version"]
            dotnet_versions.append(version)
    if not dotnet_versions:
        return ["NO .NET Framework versions found."]
    return [".NET Versions:", f".NET Framework Versions found: {', '.join(dotnet_versions)}"]
```
get_dotnet_version() queries the Windows registry for installed .NET Framework versions and returns a list of the versions found

##  classic_audit_policies
Classic Audit Policies refer to settings in Windows that determine which types of security events are logged for auditing purposes.
```python
    policy_path = r"SYSTEM\CurrentControlSet\Services\EventLog\Security"
    cap = ""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, policy_path) as key:
            cap += '\nFile Path: ' + winreg.QueryValueEx(key, 'File')[0]
            cap += '\nMax Size: ' + f"{winreg.QueryValueEx(key, 'MaxSize')[0] / (1024**2):.0f} MB"
            cap += '\nRetention Policy: ' + f"{winreg.QueryValueEx(key, 'Retention')[0]}"
            cap += '\nRestrict Guest Access: ' + f"{winreg.QueryValueEx(key, 'RestrictGuestAccess')[0]}"
    except PermissionError:
        cap = "Error: Access is denied."
    except FileNotFoundError:
        cap = "Error: Registry path not found."
    except Exception as e:
        cap = f"Unexpected error: {e}"

    return ["Classic Audit Policies:", cap]
```
The classic_audit_policies() function reads audit policy settings from   
the Windows registry under the path ``SYSTEM\CurrentControlSet\Services\EventLog\Security``  
and returns details like ``file path, maximum size, retention policy, and guest access restrictions``.

## Advance Audit Policies
The advanced_audit_policies() function checks specific Windows registry paths for enabled   
audit policies. It collects the names of the enabled policies and returns them
```python
 with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, policy_path) as key:
                i = 0
                while True:
                    try:
                        policy_name, policy_value, _ = winreg.EnumValue(key, i)
                        if policy_value == 1:
                            details += f"{policy_name}: " + "Enabled"
                            f = 0
                        i += 1
```

## get_registry_autorun_entries
```python
    for path, hive in autorun_keys.items():
        try:
            key = winreg.OpenKey(hive, path.split('\\', 1)[1])
            for i in range(winreg.QueryInfoKey(key)[1]):
                name, value, _ = winreg.EnumValue(key, i)
                autorun_entries.append((name, value, path))
            winreg.CloseKey(key)
```
the autorun entries determine programs that run automatically when the system starts

## get_scheduled_tasks
```python
    task_service = win32com.client.Dispatch("Schedule.Service")
    task_service.Connect()
    root_folder = task_service.GetFolder("\\")
```
retrieve scheduled tasks from the Windows Task Scheduler

## def get_startup_folder_entries():
```python
    startup_folders = [
        os.path.join(os.getenv("PROGRAMDATA"), "Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
        os.path.join(os.getenv("APPDATA"), "Microsoft\\Windows\\Start Menu\\Programs\\Startup")
    ]
    
    startup_entries = []
    for folder in startup_folders:
        if os.path.isdir(folder):
            for item in os.listdir(folder):
                startup_entries.append(os.path.join(folder, item))
    
    return startup_entries
```
retrieve the list of entries in the Startup folders in Windows
## get_essential_defender_settings
This function gathers key Defender settings, such as real-time protection,   
antivirus status, signature update status, the last quick scan time, and the scan schedule

## get_firewall_rules
```python
    cmd = "powershell -Command \"Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true} | ConvertTo-Json\""
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
```
execute powershell command to retrieve firewall rules

## get_installed_hotfixes
```python
    cmd = "wmic qfe list"
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
```
uses wmi to list out installed hotfixes

## get_local_users_powershell
```python
    cmd = (
        "powershell -Command \"" 
        "Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordExpires, AccountExpires, UserMayChangePassword | ConvertTo-Json\""
    )
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
```
This command uses PowerShell to fetch details about the local users on a Windows system.  
The ``Get-LocalUser`` is used to get a list of local user accounts

## get_pending_updates
```python
    cmd = (
        "powershell -Command \"" 
        "Get-WindowsUpdate -IsPending | Select-Object Title, KBArticleID, Installed, Date | ConvertTo-Json\""
    )
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
```

## get_dns_cache_entries
```python
    output = subprocess.check_output(["ipconfig", "/displaydns"], text=True)
    domain_pattern = re.compile(r"Record Name\s+:\s+([\w\.-]+)")
```
``ipconfig /displaydns`` displays the contents of the DNS resolver cache on a Windows machine
