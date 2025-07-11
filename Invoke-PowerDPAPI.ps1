function Invoke-PowerDPAPI {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [string]$Format="hex"
    )
    
    Write-Host "[*] Running PowerDPAPI"

    if(Test-Path -Path $Path) {
        $fileList = Get-ChildItem -Path $Path -File -Force -Recurse | select-object -ExpandProperty FullName

        if($fileList) {
            foreach ($file in $fileList) {
                if($VerbosePreference) {
                    Write-Host "[>] Processing file: $file"
                }

                # Number of bytes to check
                $byteCount = 1024

                # Read bytes from file
                $inputBytes = Get-Content -Path $file -Encoding Byte -TotalCount $byteCount        

                # Convert byte array to hex string
                $hexInputBytes = ($inputBytes | ForEach-Object { "{0:X2}" -f $_ }) -join ""

                # find the start index of the DPAPI blob bytes
                $magicByteIndex = $hexInputBytes.IndexOf("01000000D08C9DDF0115D1118C7A00C04FC297EB")
                # looks like a blob, let's try to process it
                if($magicByteIndex -ge 0) {        
                    $md5Hash = Get-FileHash -Path $file -Algorithm MD5 | Select-Object -ExpandProperty Hash
                    $sha1Hash = Get-FileHash -Path $file -Algorithm SHA1 | Select-Object -ExpandProperty Hash
                    $sha256Hash = Get-FileHash -Path $file -Algorithm SHA256 | Select-Object -ExpandProperty Hash

                    Write-Host "**********************************************************************"
                    Write-Host "[!] Probable DPAPI blob found"
                    Write-Host "[>] File: $file"
                    Write-Host "[>] MD5 Hash: $md5Hash"
                    Write-Host "[>] SHA-1 Hash: $sha1Hash"
                    Write-Host "[>] SHA-256 Hash: $sha256Hash"

                    if($VerbosePreference) {
                        Write-Host "[>] magicByteIndex: $magicByteIndex"
                    }

                    # read all of the bytes from the file
                    $blobFileByteArray = [System.IO.File]::ReadAllBytes($file)

                    # From: https://github.com/gentilkiwi/mimikatz/blob/master/modules/kull_m_dpapi.h#L24
                    $dwVersion = New-Object byte[] 4
                    $guidProvider = New-Object byte[] 16
                    $dwMasterKeyVersion = New-Object byte[] 4
                    $guidMasterKey = New-Object byte[] 16
                    $dwFlags = New-Object byte[] 4
                    $dwDescriptionLen = New-Object byte[] 4
                    # $szDescription = New-Object byte[] 0 # dynamic length - initialize as empty or with appropriate size if known
                    $algCrypt = New-Object byte[] 4
                    $dwAlgCryptLen = New-Object byte[] 4
                    $dwSaltLen = New-Object byte[] 4
                    # $pbSalt = New-Object byte[] 0 # dynamic length - initialize as empty or with appropriate size if known
                    $dwHmacKeyLen = New-Object byte[] 4
                    $pbHmackKey = New-Object byte[] 8
                    $algHash = New-Object byte[] 4
                    $dwAlgHashLen = New-Object byte[] 4
                    $dwHmac2KeyLen = New-Object byte[] 4
                    # $pbHmack2Key = New-Object byte[] 0 # dynamic length - initialize as empty or with appropriate size if known
                    $dwDataLen = New-Object byte[] 4
                    $dwSignLen = New-Object byte[] 4
                    # $pbSign = New-Object byte[] 0 # dynamic length - initialize as empty or with appropriate size if known
                
                    # the start index was found using a character string, divide by 2 for the byte location
                    $ptrBlob = $magicByteIndex / 2

                    # start our pointer from the masterKeyGuid position
                    $ptrBlob += $dwVersion.Length + $guidProvider.Length + $dwMasterKeyVersion.Length
                    
                    # guidMasterKey
                    [System.Array]::Copy($blobFileByteArray, $ptrBlob, $guidMasterKey, 0, $guidMasterKey.Length)
                    $ptrBlob += $guidMasterKey.Length
                    $masterKeyGuid = [System.Guid]::new($guidMasterKey)                    
                    Write-Host "[>] Master Key GUID: $masterKeyGuid"

                    # advance beyond the flags to the description length
                    $ptrBlob += $dwFlags.Length

                    # dwDescriptionLen
                    [System.Array]::Copy($blobFileByteArray, $ptrBlob, $dwDescriptionLen, 0, $dwDescriptionLen.Length)
                    $ptrBlob += $dwDescriptionLen.Length
                    
                    # convert the byte array to an integer, needed to allocate the description byte array
                    [uint32]$descriptionLength = [System.BitConverter]::ToUInt32($dwDescriptionLen, 0)
                    if($VerbosePreference) {
                        Write-Host "[>] descriptionLength: $descriptionLength"
                    }

                    if($descriptionLength -gt 0) {
                        $szDescription = New-Object byte[] $descriptionLength
                        [System.Array]::Copy($blobFileByteArray, $ptrBlob, $szDescription, 0, $descriptionLength)
                        $ptrBlob += $descriptionLength            
                        $readableDescription = [System.Text.Encoding]::UTF8.GetString($szDescription)
                        Write-Host "[>] Blob Description: $readableDescription"
                    } else {
                        Write-Host "[>] Description is empty"
                    }

                    # write bytes to stdout
                    Write-Host "-------------- START blob output --------------"
                    if($Format -eq "base64") {
                        $base64EncodedBlob = [System.Convert]::ToBase64String($blobFileByteArray)
                        Write-Host $base64EncodedBlob
                    } else {
                        ($blobFileByteArray | ForEach-Object { "\x{0:X2}" -f $_ }) -join ""
                    }
                    Write-Host "--------------  EOF blob output  --------------"        

                    Write-Host "[>] Locating corresponding master key file"

                    $protectDirectory = $Env:AppData + "\Microsoft\Protect"
                    $userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                    if($userSid) {
                        $mkDirectory = $protectDirectory + "\" + $userSid
                        $mkFilePath = $mkDirectory + "\" + $masterKeyGuid
                        
                        if($VerbosePreference) {
                            Write-Host "[>] Constructed Master Key Directory:"
                            Write-Host "    $mkDirectory"
                        }

                        if(Test-Path $mkFilePath) {
                            Write-Host "[>] Master Key Found:"
                            Write-Host "    $mkFilePath"

                            # file bytes
                            $mkByteArray = [System.IO.File]::ReadAllBytes($mkFilePath)
                            # write bytes to stdout
                            Write-Host "-------------- START master key --------------"
                            if($Format -eq "base64") {
                                $base64EncodedMk = [System.Convert]::ToBase64String($mkByteArray)
                                Write-Host $base64EncodedMk
                            } else {
                                ($mkByteArray | ForEach-Object { "\x{0:X2}" -f $_ }) -join ""
                            }
                            Write-Host "--------------  EOF master key  --------------"
                        } else {
                            Write-Host "[!] Unable to find corresponding master key using path:"
                            Write-Host "    $mkFilePath"
                        }         
                    } else {
                        Write-Host "[ERROR] Unable to determine user SID"
                    }
                }
                Write-Host "**********************************************************************"
            }
        }
    } else {
        Write-Warning "[!] ERROR: File or directory not found"
    }
    Write-Host "[*] Done."
}
