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
