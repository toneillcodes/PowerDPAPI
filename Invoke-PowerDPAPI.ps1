# Generic PS function to return an OG node
Function New-OpenGraphNode {
    Param(
		[Parameter(Mandatory = $true)]
		$NodeId, 
		[Parameter(Mandatory = $true)]
		$NodeKind, 
		[Parameter(Mandatory = $true)]
		$SourceKind, 		
		[Parameter(Mandatory = $true)]
		$Properties
	)
    
    return [pscustomobject]@{
        id         = $NodeId
        kinds      = @($NodeKind, $SourceKind)
        properties = $Properties
    }
}
# Generic PS function to return an OG edge
Function New-OpenGraphEdge {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$EdgeName,
        [Parameter(Mandatory = $true)]
        [string]$SourceNodeId,
        [Parameter(Mandatory = $true)]
        [string]$TargetNodeId,
        [Parameter(Mandatory = $false)]
        [hashtable]$Properties = @{} # Default to an empty hashtable
    )

    return [pscustomobject]@{
        kind       = $EdgeName
        start      = @{ value = $SourceNodeId }
        end        = @{ value = $TargetNodeId }
        # If $Properties is provided, it populates; if not, it's an empty {}
        properties = $Properties
    }
}

function Get-DPAPIMasterKeyInfo {
    param (
        [Parameter(Mandatory=$false)]
        [string]$Path
    )

    # Initialize placeholders
    $info = [ordered]@{
        "Username"    = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        "Owner_SID"   = "Unknown"
        "Version"     = "Unknown"
        "Iterations"  = "Unknown"
        "Salt_Hex"    = "Unknown"
        "Created_At"  = "Unknown"
        "Full_Path"   = $Path
    }

    if ($Path -and (Test-Path $Path)) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($Path)
            $fileInfo = Get-Item -LiteralPath $Path -Force
            
            # The owner SID is usually the name of the parent directory in DPAPI paths
            $info["Owner_SID"] = $fileInfo.Directory.Name 
            $info["Created_At"] = $fileInfo.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
			
            # Parsing the MasterKey Binary Structure
            # Version is at offset 0 (4 bytes)
            $info["Version"] = [System.BitConverter]::ToInt32($bytes, 0)
            
            # Salt is at offset 12 (16 bytes)
            $saltBytes = New-Object byte[] 16
            [System.Array]::Copy($bytes, 12, $saltBytes, 0, 16)
            $info["Salt_Hex"] = ($saltBytes | ForEach-Object { "{0:X2}" -f $_ }) -join ""
            
            # Rounds/Iterations is at offset 28 (4 bytes)
            $info["Iterations"] = [System.BitConverter]::ToInt32($bytes, 28)
            
            # Use the actual filename as the GUID if it's a valid GUID
            if ($fileInfo.Name -match '\{?[a-fA-F0-9-]{36}\}?') {
                $info["GUID"] = $fileInfo.Name
            }
        }
        catch {
            Write-Warning "Failed to parse MasterKey at Path: $Path"
        }
    }

    return [PSCustomObject]$info
}

function Invoke-PowerDPAPI {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,		
        [string]$Format="hex",
		[Parameter(Mandatory=$false)]
		[string]$Graph,     
        [switch]$Quiet       		
    )
    	
    Write-Host "[*] Running PowerDPAPI"

    if(Test-Path -Path $Path) {
        $fileList = Get-ChildItem -Path $Path -File -Force -Recurse | select-object -ExpandProperty FullName

		# initialize objects to prevent errors
		# collection for OG data
		$nodeList = New-Object System.Collections.Generic.List[PSObject]
		$edgeList = New-Object System.Collections.Generic.List[PSObject]
		# collection for CSV data
		$csvCollection = New-Object System.Collections.Generic.List[PSObject]
		
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
                    #$masterKeyGuid = [System.Guid]::new($guidMasterKey)    
					$masterKeyGuid = ([System.Guid]::new($guidMasterKey)).ToString()
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

					if (-not $Quiet) {
						# write bytes to stdout
						Write-Host "-------------- START blob output --------------"
						if($Format -eq "base64") {
							$base64EncodedBlob = [System.Convert]::ToBase64String($blobFileByteArray)
							Write-Host $base64EncodedBlob
						} else {
							($blobFileByteArray | ForEach-Object { "\x{0:X2}" -f $_ }) -join ""
						}
						Write-Host "--------------  EOF blob output  --------------"        
					}
					# get the file system object for the blob
					$blobFileInfo = Get-Item -LiteralPath $file -Force

					# extract properties
					$blobFileName = $blobFileInfo.Name
					$blobSize   = $blobFileInfo.Length
					$blobCreated = $blobFileInfo.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
					$blobModified = $blobFileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")

					# blobProperties hashtable
					$blobProperties = @{
						name          = $blobFileName
						full_path	  = $file
						size_bytes    = $blobSize
						created_at    = $blobCreated
						modified_at   = $blobModified
						extension     = $blobFileInfo.Extension
					}

					$dpapiBlob_Node = New-OpenGraphNode -NodeId $file -NodeKind 'DPAPIBlob' -SourceKind 'DPAPI' -Properties $blobProperties
					$null = $nodeList.Add($dpapiBlob_Node)

					# Add to CSV collection
					# todo: flatten properties
                    $null = $csvCollection.Add([PSCustomObject]$dpapiBlob_Node)

					$dpapiBlobToMk_Edge = New-OpenGraphEdge -EdgeName 'EncryptedWith'-SourceNodeId $file -TargetNodeId $masterKeyGuid
					$null = $edgeList.Add($dpapiBlobToMk_Edge)
					
					# Add to CSV collection (flattening the properties for CSV format)
					# todo: flatten properties
                    $null = $csvCollection.Add([PSCustomObject]$dpapiBlobToMk_Edge)
					
					## Let's see if we can locate the masterkey
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
					
							$mkData = Get-DPAPIMasterKeyInfo -Path $mkFilePath
							
							# Create the Node for the Master Key
							$mkNode = New-OpenGraphNode -NodeId $masterKeyGuid -NodeKind 'DPAPIMasterKey' -SourceKind 'DPAPI' -Properties $mkData
							$null = $nodeList.Add($mkNode)
							$null = $csvCollection.Add([PSCustomObject]$mkNode)
							
                            # file bytes
                            $mkByteArray = [System.IO.File]::ReadAllBytes($mkFilePath)
                            if (-not $Quiet) {
								# write bytes to stdout
								Write-Host "-------------- START master key --------------"
								if($Format -eq "base64") {
									$base64EncodedMk = [System.Convert]::ToBase64String($mkByteArray)
									Write-Host $base64EncodedMk
								} else {
									($mkByteArray | ForEach-Object { "\x{0:X2}" -f $_ }) -join ""
								}
								Write-Host "--------------  EOF master key  --------------"
							}
                        } else {
                            Write-Host "[!] Unable to find corresponding master key using path:"
                            Write-Host "    $mkFilePath"							
							# If file not found, still create a node with placeholders
							$placeholderData = Get-DPAPIMasterKeyInfo -Path "FILE_NOT_FOUND"
							$placeholderNode = (New-OpenGraphNode -NodeId $masterKeyGuid -NodeKind 'DPAPIMasterKey' -SourceKind 'DPAPI' -Properties $placeholderData)
							$null = $nodeList.Add($placeholderNode)
							# todo: flatten properties
							$null = $csvCollection.Add([PSCustomObject]$placeholderNode)							
                        }   
                    } else {
                        Write-Host "[ERROR] Unable to determine user SID"
                    }
                }
                Write-Host "**********************************************************************"
            }
					
			# --- CSV Export ---
            #if (![string]::IsNullOrWhiteSpace($Csv)) {
            #    Write-Host "[*] Exporting data to CSV: $Csv"
            #    $csvCollection | Export-Csv -Path $Csv -NoTypeInformation -Force
            #}
			
			# --- Graph Export ---
			if (![string]::IsNullOrWhiteSpace($Graph)) {
				Write-Host "[*] Graph output enabled, constructing graph object."
				$graphOutput = [PSCustomObject]@{
					metadata = [PSCustomObject]@{
						source_kind = "DPAPI"
					}
					graph = [PSCustomObject]@{
						nodes = $nodeList
						edges = $edgeList
					}
				}
				# Ensure the directory exists before writing
				$targetDir = Split-Path -Path $Graph
				if ($targetDir -and !(Test-Path $targetDir)) {
					New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
				}				
				# ConvertTo-Json only looks at the object 2 levels deep
				Write-Host "[*] Writing graph object to $Graph."
				$graphOutput | ConvertTo-Json -Depth 10 | Out-File -FilePath $Graph			
			} else {
				Write-Host "[*] No Graph path provided. Skipping OG file output."
			}
        }
    } else {
        Write-Warning "[!] ERROR: File or directory not found"
    }
    Write-Host "[*] Done."
}