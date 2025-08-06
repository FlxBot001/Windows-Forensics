# Project 1: Investigating **Windows** Event Logs for Security Incidents

## 🧠 Introduction

Windows Event Logs are a vital source of truth in the world of digital forensics and cybersecurity. They contain detailed records about system, security, and application-level activities on a Windows machine. In this project, I demonstrate how to investigate and analyze these logs to identify suspicious login behaviors that may indicate a security incident.

By the end of this project, you'll learn how to:
- Access and interpret Windows Event Logs
- Identify failed and successful login attempts
- Correlate different types of logs to detect attack patterns
- Use tools like PowerShell and Log Parser to automate analysis

---

## 🧰 Lab Setup

To follow along or reproduce this analysis, you'll need access to a Windows machine—either physical or virtual.

### ✅ Pre-requisites
- Basic understanding of Windows OS
- Familiarity with Command Prompt and PowerShell
- Administrative privileges on the Windows host

### 🔧 Tools Used                                        
| **Event Viewer** | Native GUI tool to view system & security logs 

| **PowerShell**   | Scripting and command-line automation         

| **Log Parser**   | Microsoft's powerful log query tool           

#### 💾 Installing Log Parser
1. Download from the [Microsoft Download Center](https://www.microsoft.com/en-us/download/details.aspx?id=24659)
2. Run the installer and follow the on-screen instructions
3. Launch via:  
   ```cmd
   cd "C:\Program Files (x86)\Log Parser 2.2"

## 🧪 Exercises

---

### 📁 Exercise 1: Accessing Windows Event Logs Using Event Viewer

**🎯 Objective**: Learn how to navigate the Windows Event Viewer and locate key log types.

#### 📝 Steps

1. Open Event Viewer:
   - Press `Win + R`, type `eventvwr.msc`, press `Enter`
2. Explore logs:
   - Navigate to `Windows Logs` → `Security`
3. Scroll through events and take note of `Event ID 4625` (failed login attempts)

#### ✅ Expected Outcome

You will be able to identify and view different categories of logs and spot suspicious login activity.

---

### 📤 Exercise 2: Filtering and Exporting Failed Logins

**🎯 Objective**: Extract only the relevant failed login data for analysis.

#### 📝 Steps

1. In Event Viewer, select the **Security** log  
2. Right-click → **Filter Current Log**  
3. Under **Event IDs**, enter: `4625`  
4. Click **OK** and confirm the filtered results  
5. Right-click → **Save Filtered Log File As**  
6. Save as: C:\Users\Administrator\Desktop\Windows Forensics\FailedLogins.evtx

#### ✅ Expected Outcome

A filtered `.evtx` file containing only failed login events (Event ID 4625)

---

### 📊 Exercise 3: Parsing Failed Logins Using Log Parser

**🎯 Objective**: Convert the filtered `.evtx` file into a readable CSV for analysis.

#### 📝 Steps

1. Open **Command Prompt** and navigate to the Log Parser install folder:

```cmd
cd "C:\Program Files (x86)\Log Parser 2.2"
```
2. Run the following command:
```
LogParser.exe "SELECT TimeGenerated, EventID, EventTypeName, Message INTO 'C:\Users\Administrator\Desktop\FailedLogins.csv' FROM 'C:\Users\Administrator\Desktop\Windows Forensics\FailedLogins.evtx'" -i:EVT -o:CSV
```
3. Open the generated CSV file in Excel or any text viewer.

✅ Expected Outcome
A structured .csv file showing timestamps, event types, and messages for failed logins.

### 💻 Exercise 4: Automating Log Analysis with PowerShell
**🎯 Objective**
Automate failed login extraction using PowerShell scripting.

#### 📝 Steps
1. Open PowerShell as Administrator.

2. Run the following command to display failed login attempts:

```
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} | 
Format-Table TimeCreated, Id, Message -AutoSize
```
3. To save the output to a text file:
```
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} | 
Format-Table TimeCreated, Id, Message -AutoSize | 
Out-File -FilePath "C:\Users\Administrator\Desktop\FailedLogins.txt"
```
#### ✅ Expected Outcome
A .txt file containing all failed login attempts, ready for manual or scripted review.

### 🔗 Exercise 5: Correlating Failed and Successful Logins
🎯 Objective
Link failed (4625) and successful (4624) login events to spot possible attack patterns.

**Note:** Log Parser cannot perform SQL JOINs across .evtx files — we'll use PowerShell instead.

#### 📝 Steps
*Ensure you have:*

FailedLogins.evtx (Event ID 4625)

SuccessfulLogins.evtx (Event ID 4624)

1. Run the following PowerShell script:

```
# Load failed login events
$failed = Get-WinEvent -Path "C:\Users\Administrator\Desktop\Windows Forensics\FailedLogins.evtx" |
  Where-Object { $_.Id -eq 4625 } |
  Select-Object @{n="Time";e={$_.TimeCreated}}, @{n="User";e={$_.Properties[5].Value}}, @{n="Message";e={$_.Message}}

# Load successful login events
$success = Get-WinEvent -Path "C:\Users\Administrator\Desktop\Windows Forensics\SuccessfulLogins.evtx" |
  Where-Object { $_.Id -eq 4624 } |
  Select-Object @{n="Time";e={$_.TimeCreated}}, @{n="User";e={$_.Properties[5].Value}}, @{n="Message";e={$_.Message}}

# Correlate logins by user within a 5-minute window
$correlated = foreach ($f in $failed) {
  $match = $success | Where-Object {
    $_.User -eq $f.User -and 
    [math]::Abs(($_.Time - $f.Time).TotalMinutes) -le 5
  }
  foreach ($m in $match) {
    [PSCustomObject]@{
      FailedLoginTime        = $f.Time
      FailedLoginUser        = $f.User
      FailedLoginMessage     = $f.Message
      SuccessfulLoginTime    = $m.Time
      SuccessfulLoginUser    = $m.User
      SuccessfulLoginMessage = $m.Message
    }
  }
}

# Export correlated results
$correlated | Export-Csv -Path "C:\Users\Administrator\Desktop\CorrelatedLogins.csv" -NoTypeInformation
```
#### ✅ Expected Outcome
A *.csv* file showing correlated failed and successful logins for the same user within 5 minutes — useful to identify brute-force or credential stuffing attempts.

### ✅ Conclusion
This project demonstrates how to perform a forensic investigation using Windows Event Logs.

### 🧠 Key Learnings
Event ID 4625 → Failed Logins

Event ID 4624 → Successful Logins

PowerShell + Log Parser = Powerful Automation

Correlation reveals deeper attack patterns
