# Regex IOCs – Quick Catalog (for RE & YARA)

Purpose: a practical list of common regex indicators you’ll hunt for in malware or suspicious binaries/scripts.  
Copy/paste into YARA rules (add ascii|wide|nocase as needed), scripts, or triage tools.  

Tip: treat regex hits as weak signals. Combine with structure (PE/ELF guards), file size windows, section/entropy checks, or N of M logic to cut false positives.  

--- 

## Contents  

- Network
- Windows artifacts  
- Filesystem paths  
- IDs & tokens  
- Encodings & scripts  
- Hashes  
- Usage patterns  
- Notes & pitfalls

## Network

```
# HTTP/HTTPS URL (conservative)
https?:\/\/[A-Za-z0-9\.\-]+(?:\/[^\s"]*)?

## URL (all cases)
(?i)\b(?:(?:h..p|https?|ftp):\/\/)?                
(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?
  (?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*  
  |\d{1,3}(?:\.\d{1,3}){3})                        
(?::\d{2,5})?                                      
(?:\/[^\s"'<>]*)?\b

# Protocols
\b(?:ftp|smb|tcp|udp|mqtt|ws|wss)://[^\s"]+\b

# Hostname / domain (common TLDs; expand per need)
(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.|\[\.\]))+
(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})\b

# IPv4 (bounded)
\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b

# IPv6 (simplified; good enough for triage)
\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b

# IP:Port
\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d):(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3})\b

# CIDR
\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\/(?:3[0-2]|[12]?\d)\b

# Cloud storage endpoints
\bhttps?://(?:[a-z0-9\-\.]+\.)?s3(?:[-a-z0-9]+)?\.amazonaws\.com/[^\s"]+\b
\bhttps?://[a-z0-9\-\.]+\.blob\.core\.windows\.net/[^\s"]+\b
\bhttps?://storage\.googleapis\.com/[^\s"]+\b
\bhttps?://[a-z0-9\-\.]+\.r2\.cloudflarestorage\.com/[^\s"]+\b
\bhttps?://[a-z0-9\-\.]+\.digitaloceanspaces\.com/[^\s"]+\b
\bhttps?://(?:bucket\.)?wasabisys\.com/[^\s"]+\b
\bhttps?://f\d+\.backblazeb2\.com/file/[^\s"]+\b

# Tor .onion (v2/v3 lengths)
\b[a-z2-7]{16,56}\.onion\b

# Discord webhook
(?i)\bhttps://discord\.com/api/webhooks/\d{17,20}/[A-Za-z0-9._-]{30,}\b

# Discord user/bot token (3 parts, base64-ish)
\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b

# Telegram bot token
\b\d{6,12}:[A-Za-z0-9_-]{30,}\b

# Slack webhook
(?i)\bhttps://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[A-Za-z0-9]{24}\b

# Microsoft Teams (incoming webhook-style)
(?i)\bhttps://(?:outlook|office)\.office(?:365)?\.com/webhook/[A-Za-z0-9-]{36}\@[^/\s]+/IncomingWebhook/[A-Za-z0-9-]{36}/[A-Za-z0-9-]{36}\b
```

---

## Windows artifacts

```
# Mutex name
\b(?:Global|Local)\\[A-Za-z0-9\-\{\}_]{6,64}\b

# Named pipe
\\\\\.\\pipe\\[A-Za-z0-9_\-\.]{5,64}

# Registry persistence hives
\bHK(?:LM|CU)\\[A-Za-z0-9_\\\-\s]{3,}\\(?:Run|RunOnce|Services)\\[A-Za-z0-9_\-]{2,}\b

# Scheduled tasks
\bC:\\Windows\\System32\\Tasks\\[A-Za-z0-9 _\-\\]{3,}\b

```

---

## Unix Artifacts

```
# MacOS persistence
\b(?:LaunchAgents|LaunchDaemons)\/[A-Za-z0-9_.\-]{3,}\.plist\b

# Linux cron entries
(?m)^(?:@reboot|(?:\S+\s+){5}\S+).*
```

---

## Filesystem paths

```
# Windows path (depth-limited)
[A-Za-z]:\\(?:[^\\\r\n]+\\){1,6}[^\\\r\n]+

# POSIX path (depth-limited)
\/(?:[^\s\/]+\/){1,6}[^\s\/]+

# UNC path
\\\\[A-Za-z0-9_\-\.]+\\[A-Za-z0-9_\-\.\\\$]{2,}

# Temp/Startup locations
\bC:\\Users\\[^\\]+\\AppData\\(?:Local|Roaming)\\Temp\\[^\r\n]{3,}\b
\bC:\\ProgramData\\[^\r\n]{3,}\b
\bC:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\[^\r\n]+\b

# Exe/Scripts extensions
\b[^\s"']+\.(?:exe|dll|scr|ps1|vbs|js|jse|hta|bat|cmd)\b

# Registry
\bHKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?\\[A-Za-z0-9_\-]{2,}\b
\bHKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?\\[A-Za-z0-9_\-]{2,}\b
\bHKLM\\System\\CurrentControlSet\\Services\\[A-Za-z0-9_\-]{2,}\b
```

---

## IDs & tokens

```
# GUID
\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b

# CLSID
\{[0-9A-Fa-f\-]{36}\}

# Windows SID
\bS-\d-\d+-(?:\d+-){1,14}\d+\b

# Email
\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b

# Sandbox/VM
\b(?:VBox|VMware|QEMU|VirtualBox|vboxguest|vmtools)\b

# JWT (header.payload.signature, base64url)
\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b

# Bearer
\bAuthorization:\s*(?:Bearer|Basic)\s+[A-Za-z0-9+/_\-\.=]{10,}\b
```

---

## Encodings & scripts

```
# Hex blob
\b(?:[A-Fa-f0-9]{2}){16,}\b

# Base32 blob
\b(?:[A-Z2-7]{16,})={0,6}\b

# Base64 blob (bounded to avoid noise)
\b(?:[A-Za-z0-9+\/]{20,}={0,2})\b

Gzip/Base64 header hint
\bH4sIA[A-Za-z0-9+/=]{20,}\b

# PowerShell base64 launcher
(?:powershell|pwsh)\S*\s+-enc\s+[A-Za-z0-9+\/=]{20,}

# Living-off-the-land invocations
\b(?:rundll32|regsvr32|mshta|powershell|pwsh|wscript|cscript|bitsadmin|certutil|wmic|schtasks|fodhelper|cmstp)\b

# Powershell flags
\b-power(?:s|)hell\b|\b-enc(?:odedCommand)?\b|\b-noni\b|\b-exec\b|\b-WindowStyle\s+Hidden\b

# PowerShell encoded + stealthy flags
(?i)\b(?:powershell|pwsh)\b(?:(?!\r?\n).){0,200}\s-enc(?:odedCommand)?\s+[A-Za-z0-9+\/=]{20,}
(?i)\b-(?:nop|noni|w(?:indowstyle)?\s+hidden|sta|ep\s+bypass|exec(?:utionpolicy)?\s+bypass)\b

# curl/wget with exfil/upload intent
(?i)\b(?:curl|wget)\b(?:(?!\r?\n).){0,200}\s-(?:d|F|T|X\s+PUT)\b
```

---

## Hashes

```
# MD5/SHA1/SHA256 (handy for config/log parsing)
\b[A-Fa-f0-9]{32}\b
\b[A-Fa-f0-9]{40}\b
\b[A-Fa-f0-9]{64}\b

# Certificates/Keys markers
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN (?:RSA |EC )?PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
ssh-(?:rsa|ed25519)\s+[A-Za-z0-9+/=]+

```

---

## Magic numbers

```
# DOS MZ header (PE)
(?s)\bMZ.{32,4096?}PE\0\0

# ELF
(?s)\x7FELF

# Mach-O (fat/64)
(?s)\xFE\xED\xFA\xCF|\xCA\xFE\xBA\xBE
```
