# CTFMethod
quick and dirty notes


#########################
Recon
#########################
Identify Box Owner
   Look up their github - found
   Look up their Twitter - found
   Look up their LinkedIn - not found
   Look at HTB to find other boxes they have made
######################## 
Enumeration
#########################
TCP
   Scan common ports (-f or no port specification)
   Scan all ports (-p- or -p 0-65535)
   Connect Scan - Optional
UDP
   Scan common ports
   Optional - Scan all ports (-p- or -p 0-65535)
   Manually Check (mainly because they are easy to forget/miss)
   SNMP
   DNS
   TFTP
#########################
Service Fingerprinting
#########################
   Identify Services (sV)
   Nmap Common Vulns (-sC)
Identify Operating Systems
Identify IPS/IDS/WAF/CDN/Security Technology
Look for common weaknesses and known vulnerabilities (research)
Search exploitdb from nmap output - optional
#########################
HTTP Discovery
Manually Review Site
Check HTTP resonses
Check METHODs
Check Comments
Check Site Legitimate Functionality
Look for common files e.g. robots.txt, security.txt, sitemap.xml
Check TLS Config (For flaws but also host header record leakage)
Use the site through proxy (BURP)
Crawl the site (BURP)
Force Browser/Content Discovery (WFUZZ, DIRBUSTER, BURP PRO)
Forced browse with custom content lists based on the target app etc.
NIKTO
NESSUS
OWASP ZAP
Known Unpatched Applicaiton Vulnerabilities
Depenancy Vulnerabilities
Content Security Policy Header Discovery
Common Web Vulnerabilities
 XSS
 Injection
  SQL
NOSQL
Command Injection (OS)
LDAP Injection  
 Path Traversal
 Security Misconfigurations
 Insecure File Upload
 Insecure Direct Oject Refrences (IDOR)
Broken Authentication
Session Tokens
Cookie Manipulation/tampering
XML Exernal Entities (XXE)
Insecure Deserialisation
JSON
#########################
Priviledge Escalation
#########################
#########################
Active Directory
#########################
Group Policy Preferences Passwords
Kerberoating
ASREP Roasting
Responer/LLMNR Poisoning
WPAD Poisoning
Pass the Hash
Golden Ticket
Silver Ticket
Insecure Delegation Permissions
Abusing Trusts
Passwords in active directory metadata (e.g. Descriptions)
Weak/Easily Guessable Passwords
Weak or Missing Account Lockout settings
Misconfigured ACL/DACL
Directory Replication
MIMIKATZ/IMPACKET
PowerSploit/PowerUp
SharpHound/Bloodhound
PingCastle
#########################
Microsoft Exchange
#########################
Insecure Permissions
Known Exploits
#########################
Windows Server/Client
#########################
Unquoted Service Paths
Windows Installer Always Install Elevated
Insure Credential Storage
SYSPREP Answer Files
Autologon Registry Keys
VNC
TeamViewer
Excel Files
Zip Files
TXT Files
Insecure Service/File Permissions
#########################
Linux
#########################
Kernel Exploits
Insecure Custom Binary
Insecure Linux Capabilities
Insecure CRON Jobs
CRON Path Vulnerabiltiies
CRON Wildcards
CRON File Overwrite
Insecure Scripted Jobs
Insecure SUID (Set User ID) Configuration
Docker/Container Escapes
Insecure Credentials
Application Configurations
Log Files/Debug Logs
Insecure SSH Keys (id_rsa & id_rsa.pub)
Insecure backups
Transmission of Credentials in Clear Text
Packet Capture to retrieve HTTP/TELNET/FTP credentials
Binary Exploitation
Buffer Overflow
ROP
#########################
Cloud Services
#########################
Azure AD Connect
Office 365
Azure AD
AWS
Insecure S3 Buckets
Networking
Insecure Management Interfaces
DHCP Poisoning
IPV4 MITM
IPV6 MITM
SMB Relay
#########################
Common Protocols
#########################
SMTP
FTP
SMB
LDAP
TELNET
SSH
TFTP
SNMP
Intel AMT/VPRO
DELL iDRAC
HP ILO
WINRM
NFS
IMPAP
POP3
