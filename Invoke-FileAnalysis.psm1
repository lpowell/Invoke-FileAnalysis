<#
Reverse engineering and file analysis tools

Name: Invoke-FileAnalysis

Modules:
Get-FileType X
    Uses basic file signature analysis to identify files **ChatGPT made most of the sigs lol. Will update at some point**
Get-Strings X
    Print strings from file. Supports interesting strings mode and various encodings. **To do - Need to work mopre on heuristics.**
Get-FileSummary
    Gets signature, imports, exports, sections, DLLs, and subsystem. **Look into IAT and IDT**
    Look for COFF header 0x50450000 and go 16 * 8 for IT and 15 * 8 for export and 27 * 8 for IAT 
    https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg
Get-VirusTotalAnalysis X
    Submits file information to VT for analysis **Based on SHA256 hashes**.
Get-CompressedFiles **Probably not worth it**
    Binwalk extraction functionality.
Invoke-FileAnalysis X
    Create a report on analysis modules. Supports saving to word documents. ** Will add once a template is decided. For now, redirect output with *> or Out-String.**

If fileExists is false, try appending current path to the file name and checking again. This will let users use file names instead of full paths when working in directories. 



#>


function Get-FileType([Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Enter one or more file names separated by commas")] [string[]] $Files){
<#
    .SYNOPSIS
        Get-FileType uses the first 10 bytes of a given file or series of files to determine the file type. Various file signatures are defined in the code, and more can be added following the format. 

    .EXAMPLE 
        Get-FileType "filepath1","filepath2","filepath3"

        This example submits multiple files for analysis.
#>
    function Results([string]$Type, [string]$FilePath, [string]$FileHash) {
        $Results = [PSCustomObject]@{
            Signatures = @{
                "4D 5A"=[PSCustomObject][Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="EXE,DLL,MUI,SYS,SCR,CPL,OCX,AX,IEC,IME,RS,TSP,FON,EFI"
                    "Description"="DOS MZ executable and its descendants (including NE and PE)"
                };
                "23 21"=[PSCustomObject][Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"=""
                    "Description"="Script or data to be passed to the program following the shebang (#!)"
                };
                "FF D8"=[PSCustomObject][Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="JPG,JPEG"
                    "Description"="JPEG/JFIF image file"
                };
                "89 50 4E 47 0D 0A 1A 0A"=[PSCustomObject][Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="PNG"
                    "Description"="PNG image file"
                };
                "49 44 33"=[PSCustomObject][Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="MP3"
                    "Description"="MP3 audio file with ID3 tag"
                };
                "1F 8B 08"=[PSCustomObject][Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="GZ,TAR,TAR.GZ"
                    "Description"="GZIP compressed TAR archive"
                };
                "25 50 44 46"=[PSCustomObject][Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="PDF"
                    "Description"="Adobe PDF document"
                };
                "50 4B 03 04"=[PSCustomObject][Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="ZIP"
                    "Description"="ZIP archive"
                };
                "D0 CF 11 E0 A1 B1 1A E1"=[PSCustomObject][Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="DOC"
                    "Description"="Microsoft Word Document (97-2003)"
                };
                "50 4B 03 04 14 00"=[PSCustomObject][Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="DOCX, PPTX"
                    "Description"="Microsoft Word Document (2007 and later)"
                };
                "FF FB"=[PSCustomObject][Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="OGG"
                    "Description"="Ogg Vorbis audio file"
                };
                "1A 45 DF A3"=[PSCustomObject][Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="COM"
                    "Description"="DOS executable file"
                };
                "CA FE BA BE"=[PSCustomObject][Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="CLASS"
                    "Description"="Java class file"
                };
                "72 72 65 3C"=[PSCustomObject][Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="JAR"
                    "Description"="Java Archive file"
                };
                "37 7A BC AF 27 1C"=[PSCustomObject][Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="7Z"
                    "Description"="7-Zip archive file"
                };
                "52 49 46 46"=[PSCustomObject][Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="AVI"
                    "Description"="Audio Video Interleave (AVI) file"
                };
                "0A 0D 0D 0A 44 00 00 00 4D 3C"=[PSCustomObject][Ordered]@{
                    "FilenName"=$FilePath
                    "FileHash"=$FilePath
                    "Signature"=$Type
                    "Extensions"="PCAP"
                    "Description"="WireShark PCAP file"
                };
                "Undetermined"=[PSCustomObject][Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"=""
                    "Description"="Undetermined file type."
                }
                # Add more signatures and descriptions as needed
            }            
        }
        switch -Wildcard ($Type){
            "4D 5A*" {
                $Results.Signatures | Select-Object -ExpandProperty "4D 5A"
                Write-Host
                break
            }
            "23 21*" {
                $Results.Signatures | Select-Object -ExpandProperty "23 21"
                Write-Host
                break
            }
            "FF D8*" {
                $Results.Signatures | Select-Object -ExpandProperty "FF D8"
                Write-Host
                break
            }
            "89 50 4E 47 0D 0A 1A 0A*" {
                $Results.Signatures | Select-Object -ExpandProperty "89 50 4E 47 0D 0A 1A 0A"
                Write-Host
                break
            }
            "49 44 33*" {
                $Results.Signatures | Select-Object -ExpandProperty "49 44 33"
                Write-Host
                break
            }
            "1F 8B 08*" {
                $Results.Signatures | Select-Object -ExpandProperty "1F 8B 08"
                Write-Host
                break
            }
            "25 50 44 46*" {
                $Results.Signatures | Select-Object -ExpandProperty "25 50 44 46"
                Write-Host
                break
            }            
            "50 4B 03 04*" {
                if(($FilePath.Substring($FilePath.Length -4, 4) -eq "docx") -or ($FilePath.Substring($FilePath.Length -4, 4) -eq "pptx")){
                    $Results.Signatures | Select-Object -ExpandProperty "50 4B 03 04 14 00"
                    Write-Host
                    break
                }elseif(($FilePath.Substring($FilePath.Length -3, 3) -eq "zip")){
                    $Results.Signatures | Select-Object -ExpandProperty "50 4B 03 04"
                    Write-Host
                    break
                }else{
                    Write-Host "Cannot determine if this is a DOCX or ZIP based on file header"
                    $Results.Signatures | Select-Object -ExpandProperty "Undetermined"
                    Write-Host
                    break
                }
            }
            "D0 CF 11 E0 A1 B1 1A E1*" {
                $Results.Signatures | Select-Object -ExpandProperty "D0 CF 11 E0 A1 B1 1A E1"
                Write-Host
                break
            }
            "FF FB*" {
                $Results.Signatures | Select-Object -ExpandProperty "FF FB"
                Write-Host
                break
            }
            "1A 45 DF A3*" {
                $Results.Signatures | Select-Object -ExpandProperty "1A 45 DF A3"
                Write-Host
                break
            }
            "CA FE BA BE*" {
                $Results.Signatures | Select-Object -ExpandProperty "CA FE BA BE"
                Write-Host
                break
            }
            "72 72 65 3C*" {
                $Results.Signatures | Select-Object -ExpandProperty "72 72 65 3C"
                Write-Host
                break
            }
            "37 7A BC AF 27 1C*" {
                $Results.Signatures | Select-Object -ExpandProperty "37 7A BC AF 27 1C"
                Write-Host
                break
            }
            "52 49 46 46*" {
                $Results.Signatures | Select-Object -ExpandProperty "52 49 46 46"
                Write-Host
                break
            }
            "0A 0D 0D 0A 44 00 00 00 4D 3C"{
                $Results.Signatures | Select-Object -ExpandProperty "0A 0D 0D 0A 44 00 00 00 4D 3C"
                Write-Host
                break
            }
            default {
                $Results.Signatures | Select-Object -ExpandProperty "Undetermined"
                Write-Host
                break
            }
        }        
    }
   foreach($x in $Files){
    try {
        if(-Not ([System.IO.File]::Exists($x))){
            throw 
        }
        $ByteArray = [System.Byte[]]::CreateInstance([System.Byte], 10) 
        $FilePath = (Get-ChildItem -LiteralPath $x).FullName
        $FileHash = (Get-FileHash -LiteralPath $x).Hash
        $FileReader = New-Object System.IO.FileStream($x, "Open")
        $FileReader.Read($ByteArray, 0, 10) | Out-Null
        $ByteArray = [System.Convert]::ToHexString($ByteArray)
        $ByteArray = $ByteArray -replace '..(?!$)','$0 '
        $FileReader.Dispose() 
        results $ByteArray $FilePath $FileHash
        # $x=[System.Management.Automation.WildcardPattern]::Escape($x)
    }
    catch {
        $FileReader.Dispose() 
        $error[0]
    }finally{
        # If interrupt
        $FileReader.Dispose() 
        $FileReader.Close()
    }
   }
}
function Get-Strings([Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Enter one or more file paths separated by commas")] [string[]] $Files) {
<#
    .SYNOPSIS
        Get-Strings returns the strings (4 printable ASCII characters or more) of a file or list of files.

    .EXAMPLE
        Get-Strings "filepath1","filepath2","filepath3"

        This example returns strings from the file list.
#>
    foreach($x in $Files){
        try {
            # Test if file exists
            if(-Not ([System.IO.File]::Exists($x))){
                throw
            }
            
            # Create empty byte object
            $Bytes = @()

            # Open file 
            $StreamReader = New-Object System.IO.StreamReader($x)

            # Operate while file is open
            while(!$StreamReader.EndOfStream){

                # Read a byte from the file
                $Bytes = $StreamReader.Read()

                # If the byte is ASCII, add it to a string object
                if($Bytes -ge 32 -and $bytes -le 126){
                    $string += [char]$Bytes
                } else {

                    # If the string is longer than 4 characters and the current byte is null or a newline, print the string
                    if($String.length -ge 4 -and ($Bytes -eq "`0" -or $Bytes -eq "`n")){
                        $string
                        $string = ""
                    }else {

                        # If the string is not 4 characters and a non-ASCII byte is read, clear the string
                        $String = ""
                    }
                }
            }
            $StreamReader.Dispose()   
        }
        catch{
            $StreamReader.Dispose() 
            $error[0]
        }finally{
            # If interrupt
            $StreamReader.Dispose() 
        }
    }
}
function Get-VirusTotalAnalysis([Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Enter one or more file paths separated by commas")] [string[]] $Files, [Parameter(Mandatory=$false,ValueFromPipeline=$false,HelpMessage="VirusTotal API Key")] [string] $APIKey) {
<#
    .SYNOPSIS
        Get-VirusTotalAnalysis returns the VirusTotal results of any given file or file list. API keys are saved once used, and do not need to be provided in subsequent use. File hashes are submitted for analysis.

    .EXAMPLE
        Get-VirusTotalAnalyis "filepath1","filepath2","filepath3" -APIKey <apikey>

        This example returns the detection statistics of the given files. 
#>
    foreach($x in $Files){
        try {
            if(-Not ([System.IO.File]::Exists($x))){
                throw "Files does not exist"
            }
            if(!$APIKey){
                try {
                    $APIKey = [System.Environment]::GetFolderPath("MyDocuments")
                    [PSCustomObject]$APIKey = Get-Content "$APIKey\Invoke-FileAnalysis\APIKeys.json" -Raw |ConvertFrom-Json
                    $APIKey = $APIKey.VTAPI 
                }
                catch {
                    Write-Error "VirusTotal API Key not found and not supplied. Exiting..."
                    exit
                }
            }else{
                $SaveKey = [PSCustomObject]@{
                    VTAPI = $APIKey
                }
                $Documents = [System.Environment]::GetFolderPath("MyDocuments")
                if([System.IO.Directory]::Exists("$Documents\Invoke-FileAnalysis")){
                    ConvertTo-Json $SaveKey | Out-File "$Documents\Invoke-FileAnalysis\APIKeys.json"
                }else{
                    New-Item -Path "$Documents" -Name "Invoke-FileAnalysis" -ItemType Directory
                    ConvertTo-Json $SaveKey | Out-File "$Documents\Invoke-FileAnalysis\APIKeys.json"
                }
            }
            $hash = (Get-FileHash -LiteralPath $x).Hash
            $Request = Invoke-WebRequest -SessionVariable VirusTotal -Uri "https://www.virustotal.com/api/v3/files/$hash" -Method Get -Headers @{"x-apikey"=$APIKey} -SkipHttpErrorCheck
            if($Request.StatusCode -ne 200){
                Write-Host $Files
                Write-Error "Failed to retrieve VirusTotal results." 
                Write-Host 
            }else{
                $Content = $Request.Content | ConvertFrom-Json -AsHashtable
                if($Content.data.attributes.last_analysis_stats.malicious -ge 5){
                    $Determination = "Malicious"
                }elseif($Content.data.attributes.last_analysis_stats.malicious -ge 1 -Or $Content.data.attributes.last_analysis_stats.suspicious -ge 1){
                    $Determination = "Suspicious"
                }else{
                    $Determination = "Harmless"
                }
                $Results = [PSCustomObject][Ordered]@{
                    File = $x
                    Determination = $Determination
                    Malicious = $Content.data.attributes.last_analysis_stats.malicious
                    Suspicious = $Content.data.attributes.last_analysis_stats.suspicious
                    Harmless = $Content.data.attributes.last_analysis_stats.harmless
                    Link = ($Content.data.links.self).replace("/api/v3/files/", "/gui/file/")
                }
                $Results
            }
        }
        catch {
            $error[0]
        }
    }
}

function Invoke-PEAnalysis([Parameter(Mandatory=$true,ValueFromPipeline=$True,HelpMessage="Enter one or more file paths separated by commas")] [string]$Files, [Parameter(Mandatory=$false,ValueFromPipeline=$false,HelpMessage="Print all imports")] [switch]$PrintAll){
foreach($file in $Files){
    try {
        if(-Not ([System.IO.File]::Exists($file))){
            throw "File does not exist"
        }

        # Open file
        $COFFHeader = [System.Byte[]]::CreateInstance([System.Byte], 24) 
        $FileReader = New-Object System.IO.FileStream($file, "Open")

        # Get COFF Header [24 bytes]
        $FileREader.Seek(128, 0) | Out-Null
        $FileReader.Read($COFFHeader, 0, 24) | Out-Null

        # Get size of optional header for later use
        $SizeOfOptionalHeader = $COFFHeader[20..21]
        [array]::Reverse($SizeOfOptionalHeader)
        $SizeOfOptionalHeader = [System.Convert]::ToInt64([System.Convert]::ToHexString($SizeOfOptionalHeader),16)
        if($SizeOfOptionalHeader -gt 0){
            $OptionalHeader = $true
            
            # Build optional header array based on size
            $OptionalHeaders = [System.Byte[]]::CreateInstance([System.Byte], $SizeOfOptionalHeader)
        }else{
            $OptionalHeader = $false
        }

        # Read optional header [Sequential X bytes after COFF header]
        $FileReader.Read($OptionalHeaders, 0, $SizeOfOptionalHeader) | Out-Null

        # Get Sections
        $Sections = $COFFHeader[6]

        # Section Tables
        $SectionsTableStrings = @{}
        for($i=0;$i -lt $Sections;$i++){
            $SectionsTable = [System.Byte[]]::CreateInstance([System.Byte], 40) 
            $FileReader.Read($SectionsTable, 0, 40) | Out-Null
            $SectionsTableStrings[$i] = @{}
            $SectionsTableStrings[$i]["Name"] = $SectionsTable[0..7]
            $SectionsTableStrings[$i]["VirtualSize"] = $SectionsTable[8..11]
            $SectionsTableStrings[$i]["VirtualAddress"] = $SectionsTable[12..15]
            $SectionsTableStrings[$i]["SizeOfRawData"] = $SectionsTable[16..19]
            $SectionsTableStrings[$i]["PointerToRawData"] = $SectionsTable[20..23]
            $SectionsTableStrings[$i]["PointerToRelocations"] = $SectionsTable[24..27]
            $SectionsTableStrings[$i]["PointerToLinenumbers"] = $SectionsTable[28..31]
            $SectionsTableStrings[$i]["NumberOfRelocations"] = $SectionsTable[32..33]
            $SectionsTableStrings[$i]["NumberOfLinenumbers"] = $SectionsTable[34..35]
            $SectionsTableStrings[$i]["Characteristics"] = $SectionsTable[36..39]

            # Reverse arrays
            [Array]::Reverse($SectionsTableStrings[$i]["VirtualSize"])
            [Array]::Reverse($SectionsTableStrings[$i]["VirtualAddress"])
            $SectionsTableStrings[$i]["VirtualAddress"] = [System.Convert]::ToHexString($SectionsTableStrings[$i]["VirtualAddress"])
            [Array]::Reverse($SectionsTableStrings[$i]["PointerToRawData"])
            $SectionsTableStrings[$i]["PointerToRawData"] = [System.Convert]::ToHexString($SectionsTableStrings[$i]["PointerToRawData"])

            
            # Get Names
            $SectionNames = $null
            foreach($x in $SectionsTableStrings[$i]['Name']){
                $SectionNames += [char]$x
            }
            $SectionsTableStrings[$i]["Name"] = $SectionNames -join ''
        }

        # Operate on raw arrays

        # Optional Header section
        if($OptionalHeader){
            # Determine PE type from Optional Header Magic number
            $OptionalMagic = $OptionalHeaders[0..1]
            [array]::Reverse($OptionalMagic)
            $OptionalMagic = [System.Convert]::ToHexString($OptionalMagic)
            switch ($OptionalMagic) {
                '010B' { $PEType = "PE32";break }
                '020B' { $PEType = "PE32+";break}
                '0107' { $PEType = "ROM";break}
                Default {Write-Host "Unable to determine PE type"}
            }

            # Get size of .text section
            $TextSize = $OptionalHeaders[4..7]
            [Array]::Reverse($TextSize)
            $TextSize = [System.Convert]::ToInt64([System.Convert]::ToHexString($TextSize),16)

            # Get entry points
            $AddressOfEntryPoint = $OptionalHeaders[16..19]
            [array]::Reverse($AddressOfEntryPoint)
            $AddressOfEntryPoint = [System.Convert]::ToHexString($AddressOfEntryPoint)
            $AddressOfEntryPoint = $AddressOfEntryPoint -replace '..(?!$)','$0 '
            $BaseOfCode = $OptionalHeaders[20..23]

            # Break between PE32 and PE32+ formats
            if($PEType -eq "PE32"){
                $BaseOfData = $OptionalHeaders[24..27]

                # Get entry point of first byte
                $ImageBase = $OptionalHeaders[28..31]
                [Array]::Reverse($ImageBase)
                $ImageBase = [System.Convert]::ToHexString($ImageBase)
                $ImageBase = $ImageBase -replace '..(?!$)','$0 '

                # Section and File alignment
                $SectionAlignment = $OptionalHeaders[32..25]
                $FileAlignment = $OptionalHeaders[36..39]

                # Size of Image
                $SizeOfImage = $OptionalHeaders[56..59]
                [array]::Reverse($SizeOfImage)
                $SizeOfImage = [System.Convert]::ToInt64([System.Convert]::ToHexString($SizeOfImage),16)

                # Size of Headers
                $SizeOfHeaders = $OptionalHeaders[60..63]
                [array]::Reverse($SizeOfHeaders)
                $SizeOfHeaders = [System.Convert]::ToInt64([System.Convert]::ToHexString($SizeOfHeaders),16)

                # CheckSum
                $CheckSum = $OptionalHeaders[64..67]
                [Array]::Reverse($CheckSum)
                $CheckSum = [System.Convert]::ToHexString($CheckSum)
                $CheckSum = $CheckSum -replace '..(?!$)','$0 '
                
                # Export Table
                $ExportTable = $OptionalHeaders[96..103]


                # Import Table
                $ImportTable = $OptionalHeaders[104..111]
                [array]::Reverse($ImportTable)
                

                # Resource Table
                $ResourceTable = $OptionalHeaders[112..119]

                # Exception Table
                $ExceptionTable = $OptionalHeaders[120..127]

                # IAT
                $IAT = $OPtionalHeaders[192..199]
                [array]::Reverse($IAT)
                $IAT = [System.Convert]::ToHexString($IAT)
                $IAT = $IAT -replace '..(?!$)','$0 '

                # CLR Runtime Header = .NET Header 
                # First DWORD is offset [4..7], second is size [0..3]
                $CLRRuntimeHeader = $OptionalHeaders[208..215]
                [Array]::Reverse($CLRRuntimeHeader)



            }elseif($PEType -eq "PE32+"){
                # Get entry point of first byte
                $ImageBase = $OptionalHeaders[24..31]
                [Array]::Reverse($ImageBase)
                $ImageBase = [System.Convert]::ToHexString($ImageBase)
                $ImageBase = $ImageBase -replace '..(?!$)','$0 '

                # Section and File alignment
                $SectionAlignment = $OptionalHeaders[32..25]
                $FileAlignment = $OptionalHeaders[36..39]

                # Size of Image
                $SizeOfImage = $OptionalHeaders[56..59]
                [array]::Reverse($SizeOfImage)
                $SizeOfImage = [System.Convert]::ToInt64([System.Convert]::ToHexString($SizeOfImage),16)

                # Size of Headers
                $SizeOfHeaders = $OptionalHeaders[60..63]
                [array]::Reverse($SizeOfHeaders)
                $SizeOfHeaders = [System.Convert]::ToInt64([System.Convert]::ToHexString($SizeOfHeaders),16)

                # CheckSum
                $CheckSum = $OptionalHeaders[64..67]
                [Array]::Reverse($CheckSum)
                $CheckSum = [System.Convert]::ToHexString($CheckSum)
                $CheckSum = $CheckSum -replace '..(?!$)','$0 '
                
            }

            # Get Import Directory Table
            # Find what section IDT is in
            for($i=0;$i -lt $Sections;$i++){
                if([System.Convert]::ToInt64($SectionsTableStrings[$i]["VirtualAddress"], 16) -lt [System.Convert]::ToInt64([System.Convert]::ToHexString($ImportTable[4..7]), 16) -And ([System.Convert]::ToInt64($SectionsTableStrings[$i]["VirtualAddress"], 16) + [System.Convert]::ToInt64([System.Convert]::ToHexString($SectionsTableStrings[$i]["VirtualSize"]), 16)) -gt [System.Convert]::ToInt64([System.Convert]::ToHexString($ImportTable[4..7]), 16)){
                    # Write-Host "IDT is in:"$SectionsTableStrings[$i]["Name"]
                    $IDTOffset = [System.Convert]::ToInt64([System.Convert]::ToHexString($ImportTable[4..7]), 16) - [System.Convert]::ToInt64($SectionsTableStrings[$i]["VirtualAddress"], 16)
                    $IDTSeek = $IDTOffset + [System.Convert]::ToInt64($SectionsTableStrings[$i]["PointerToRawData"], 16)
                }
            }
            # Parse IDT for DLLs
            # 20 null bytes after first IDT
            # Hash table to store results
            # Get section from sectiontable to replace 0 in sectiontable hashtable
            $ImportDirectoryTable = @{}

            try{
                for($i=0;;$i++){
                    # Seek offset
                    $FileReader.Seek($IDTSeek, 0) | Out-Null
                    $IDTArray = [System.Byte[]]::CreateInstance([System.Byte], 20) 
                    $FileReader.Read($IDTArray, 0, 20) | Out-Null
                    
                    # If the NameRVA is empty, exit loop
                    if([System.Convert]::ToInt64([System.Convert]::ToHexString($IDTArray[12..15]), 16) -eq 0){
                        throw
                    }

                    # Initialize $i as a hashtable
                    $ImportDirectoryTable[$i] = @{}

                    # Read DLL Name RVA
                    $ImportDirectoryTable[$i]["NameRVA"] = $IDTArray[12..15]
                    [Array]::Reverse($ImportDirectoryTable[$i]["NameRVA"])

                    # Read DLL ILT RVA
                    $ImportDirectoryTable[$i]["ILTRVA"] = $IDTArray[0..3]
                    [Array]::Reverse($ImportDirectoryTable[$i]["ILTRVA"])

                    # Use ILT RVA to get location of import name
                    $ImportLookupTableOffset = [System.Convert]::ToInt64([System.Convert]::ToHexString($ImportDirectoryTable[$i]["ILTRVA"]), 16) - [System.Convert]::ToInt64($SectionsTableStrings[0]["VirtualAddress"], 16)
                    $ImportLookupTableSeek = $ImportLookupTableOffset + [System.Convert]::ToInt64($SectionsTableStrings[0]["PointerToRawData"], 16)

                    # Use Name RVA to get location of Name 
                    $ImportDirectoryOffset = [System.Convert]::ToInt64([System.Convert]::ToHexString($ImportDirectoryTable[$i]["NameRVA"]), 16) - [System.Convert]::ToInt64($SectionsTableStrings[0]["VirtualAddress"], 16)
                    $ImportNameSeek = $ImportDirectoryOffset + [System.Convert]::ToInt64($SectionsTableStrings[0]["PointerToRawData"], 16)

                    # Seek name
                    $FileReader.Seek($ImportNameSeek, 0) | Out-Null
                    $ImportDLLArray = [System.Byte[]]::CreateInstance([System.Byte], 20)  
                    $FileReader.Read($ImportDLLArray, 0, 20) | Out-Null

                    # Seek ILT name
                    $FileReader.Seek($ImportLookupTableSeek, 0) | Out-Null
                    $ImportLookupArray = [System.Byte[]]::CreateInstance([System.Byte], 25) 
                    $FileReader.Read($ImportLookupArray, 0, 25) | Out-Null

                    # Parse ILT Name 
                    $ImportLookupName = $null
                    foreach($x in $ImportLookupArray[10..25]){
                        if($x -ne 0){
                            $ImportLookupName += [char]$x
                        }else{
                            break
                        }
                    }

                    # Parse DLL name
                    $ImportDLLName = $null
                    foreach($x in $ImportDLLArray){
                        if($x -ne 0){
                            $ImportDLLName += [char]$x
                        }else{
                            break
                        }
                    }
                    # DLL
                    # write-host "DLLName:" $ImportDLLName
                    # ILT _CorExeMain for executables and _CorDllMain for DLLs
                    # Write-Host "DLL Import:" $ImportLookupName
                    $IDTSeek += 20 
                }
            }catch{}

            # Parse CLR Runtime Header to get EntryPoint of metadata streams
            # Use CLRRuntime RVA and size to get NETHeader
            # https://www.codeproject.com/Articles/12585/The-NET-File-Format
            $NETheaderRVA = $CLRRuntimeHeader[4..7]
            $NETHeaderOffset = [System.Convert]::ToInt64([System.Convert]::ToHexString($NETheaderRVA), 16) - [System.Convert]::ToInt64($SectionsTableStrings[0]["VirtualAddress"], 16)
            $NETHeaderSeek = $NETHeaderOffset + [System.Convert]::ToInt64($SectionsTableStrings[0]["PointerToRawData"], 16)
            $FileReader.Seek($NETHeaderSeek, 0) | Out-Null
            $NETHeaderArray = [System.Byte[]]::CreateInstance([System.Byte], [System.Convert]::ToInt64([System.Convert]::ToHexString($CLRRuntimeHeader[0..3]), 16))
            $Filereader.Read($NETHeaderArray, 0, [System.Convert]::ToInt64([System.Convert]::ToHexString($CLRRuntimeHeader[0..3]), 16)) | Out-Null
            
            # Get MetaData RVA & size
            $NETMetaDataRVA = $NETHeaderArray[8..11]
            [Array]::Reverse($NETMetaDataRVA)
            $NETMetaDataSize = $NETHeaderArray[12..15]
            [array]::Reverse($NETMetaDataSize)            
            
            # Get EntryPointToken
            $NETEntryPointToken = $NETHeaderArray[20..23]
            [array]::Reverse($NETEntryPointToken)

            # Get EntryPoint RVA / Resources RVA
            $NETEntryPointRVA = $NETHeaderArray[24..27]
            [Array]::Reverse($NETEntryPointRVA)

            # Get MetaData header from RVA
            $MetaDataOffset = [System.Convert]::ToInt64([System.Convert]::ToHexString($NETMetaDataRVA), 16) - [System.Convert]::ToInt64($SectionsTableStrings[0]["VirtualAddress"], 16)
            $MetaDataSeek = $MetaDataOffset + [System.Convert]::ToInt64($SectionsTableStrings[0]["PointerToRawData"], 16)
            $FileReader.Seek($MetaDataSeek, 0) | Out-Null
            $MetaDataArray = [System.Byte[]]::CreateInstance([System.Byte], [System.Convert]::ToInt64([System.Convert]::ToHexString($NETMetaDataSize[0..3]), 16))
            $Filereader.Read($MetaDataArray, 0, [System.Convert]::ToInt64([System.Convert]::ToHexString($NETMetaDataSize[0..3]), 16)) | Out-Null

            # Get the StreamHeader from the MetaData Header
            # Need to find the length of the version string first to ensure that the proper offset is read
            $MetaDataHeaderStringSize = $MetaDataArray[12..15]
            [array]::Reverse($MetaDataHeaderStringSize)
            $MetaDataHeaderStringSize = [System.Convert]::ToInt64([System.Convert]::ToHexString($MetaDataHeaderStringSize), 16)

            # Get number of streams
            $MetaDataStreams = $MetaDataArray[($MetaDataHeaderStringSize + 18)..($MetaDataHeaderStringSize + 19)]
            [Array]::Reverse($MetaDataStreams)
            $MetaDataStreams = [System.Convert]::ToInt64([System.Convert]::ToHexString($MetaDataStreams), 16)

            # Loop through sections
            $StreamIterations = $MetaDataHeaderStringSize + 28
            $MetaDataStreamHeaders = $MetaDataArray[($MetaDataHeaderStringSize + 20)..($MetaDataHeaderStringSize + 27)]

            $MetaDataStream = @{}
            for($i=0; $i -lt $MetaDataStreams; $i++){

                # Store current streamheaders in hashtable 
                [Array]::Reverse($MetaDataStreamHeaders)
                $MetaDataStream[$i] = @{}
                $MetaDataStream[$i]["Offset"] = $MetaDataStreamHeaders[4..7]
                $MetaDataStream[$i]["Size"] = $MetaDataStreamHeaders[0..3]

                try {
                    # Loop to get the name and find the first non-null byte after 
                    $StreamName = $null
                    
                    # For loop based on stream iterations (offset for each byte based on start of stream headers)
                    for(;;$StreamIterations++){

                        # If streamname has not been written, make sure first char is 23 / #
                        if($null -eq $StreamName -And [char]$MetaDataArray[$StreamIterations] -eq "#"){

                            # Write the name of the stream to the StreamName 
                            $StreamName += [char]$MetaDataArray[$StreamIterations]

                        # if StreamName is not null and byte is not null and no null bytes have been seen
                        }elseif(($null -ne $StreamName) -And ($MetaDataArray[$StreamIterations] -ne 0)){

                            # Write the name of the stream to the StreamName 
                            $StreamName += [char]$MetaDataArray[$StreamIterations]

                        # If a null byte is seen and the StreamName has been written, terminate
                        }elseif(($StreamName.Length -ge 2) -And $MetaDataArray[$StreamIterations] -eq 0){
                            $MetaDataStream[$i]["Name"] = $StreamName
                            throw 
                        }
                    }                    
                }
                catch {
                    # Throw to exit
                }

                # Get the Offset and Size of each section
                # Location of the end of the previous name + 8 
                $MetaDataStreamHeaders = $MetaDataArray[$StreamIterations..($StreamIterations+9)]


            }

            # Get the #~ stream RVA [MetaData offset] $MetaDataArray[$StreamRVA] (?)
            # Get the #strings RVA to find the start of the #strings stream heap
            for($i=0;$i -lt $MetaDataStreams;$i++){
                if($MetaDataStream[$i]["Name"] -eq "#~"){

                    # Get the offset of the #~ table
                    $MetaDataTableOffset = [System.Convert]::ToInt64([System.Convert]::ToHexString($MetaDataStream[$i]["Offset"]), 16) + $MetaDataSeek
                }
                if($MetaDataStream[$i]["Name"] -eq "#Strings"){

                    # Get the offset of the strings table
                    $StringsDataTableOffset = [System.Convert]::ToInt64([System.Convert]::ToHexString($MetaDataStream[$i]["Offset"]), 16) + $MetaDataSeek
                    $StringsHeapSize = [System.Convert]::ToInt64([System.Convert]::ToHexString($MetaDataStream[$i]["Size"]), 16)
                }
            }

            # Get String Heap 
            # Read entire heap and apply offset as numeric starting point as in Stream parsing
            $StringHeap = [System.Byte[]]::CreateInstance([System.Byte], $StringsHeapSize)
            $FileReader.Seek($StringsDataTableOffset, 0) | Out-Null
            $Filereader.Read($StringHeap, 0, $StringsHeapSize) | Out-Null


            # Parse the #~ MetaData Table 
            $MetaDataTable = [System.Byte[]]::CreateInstance([System.Byte], 24)
            $FileReader.Seek($MetaDataTableOffset, 0) | Out-Null
            $Filereader.Read($MetaDataTable, 0, 24) | Out-Null


            # Calculate tables present from Valid bitmask
            # Convert to binary and count 1s
            $ValidBitmask = $MetaDataTable[8..15]
            [Array]::Reverse($ValidBitmask)
            $BinaryTables = [System.Convert]::ToString([System.Convert]::ToInt64([System.Convert]::ToHexString($ValidBitmask), 16), 2)

            # Determine slots occupied with 1
            $occupiedSlots = @()
            for ($i = 0; $i -lt $BinaryTables.Length; $i++) {
                if ($BinaryTables[$i] -eq '1') {
                    $occupiedSlots += $BinaryTables.Length - $i
                }
            }
            
            # Get size arrays
            # foreach count get size
            $TableSizeArray = @{}
            [Array]::Reverse($occupiedSlots)
            foreach($i in $occupiedSlots){
                $TableSizeArray[$i] = @{}
                $TableSizeArray[$i]["Size"] = [System.Byte[]]::CreateInstance([System.Byte],4)
                $FileReader.Read($TableSizeArray[$i]["Size"], 0, 4)  | Out-Null
                [Array]::Reverse($TableSizeArray[$i]["Size"])
                $TableSizeArray[$i]["Size"] = [System.Convert]::ToInt64([System.Convert]::ToHexString($TableSizeArray[$i]["Size"]), 16)
            }

            # If $i = needed table, read the table. Else, skip $i["Size"] bytes
            # offset by 1 because of array style
            # Define arrays within the cases
            # Each table needs to be defined to skip as they are variable lengths
            foreach($i in $occupiedSlots){
                switch($i){

                    # Module
                    1 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 10), 1) | Out-Null}

                    # TypeRef
                    2 {
                        $TypeRefMembers = @{}
                        $TypeRefNames = @()
                        $TypeRefNamespace = @()
                        for($j=0;$j -lt $TableSizeArray[2]["Size"];$j++){
                            $TypeRef = [System.Byte[]]::CreateInstance([System.Byte], 6)
                            $TypeRefMembers[$j] = @{}
                            $FileReader.Read($TypeRef, 0, 6) | Out-Null

                            # Set offset to name
                            $TypeRefMembers[$j]["Name"] = $TypeRef[2..3]
                            [Array]::Reverse($TypeRefMembers[$j]["Name"])

                            # Set offset to namespace
                            $TypeRefMembers[$j]["Namespace"] = $TypeRef[4..5]
                            [Array]::Reverse($TypeRefMembers[$j]["Namespace"])
                         
                            # Get Name
                            $ObjName = $null
                            foreach($x in $StringHeap[([System.Convert]::ToInt64([SYstem.Convert]::ToHexString($TypeRefMembers[$j]["Name"]), 16))..([System.Convert]::ToInt64([SYstem.Convert]::ToHexString($TypeRefMembers[$j]["Name"]), 16) + 30)]){
                                if($x -ne 0){
                                    $ObjName += [char]$x
                                }else{
                                    break
                                }
                            }
                            $TypeRefNames += $ObjName

                            # Get Namespace
                            $ObjNamespace = $null
                            foreach($x in $StringHeap[([System.Convert]::ToInt64([SYstem.Convert]::ToHexString($TypeRefMembers[$j]["Namespace"]), 16))..([System.Convert]::ToInt64([SYstem.Convert]::ToHexString($TypeRefMembers[$j]["Namespace"]), 16) + 30)]){
                                if($x -ne 0){
                                    $ObjNamespace += [char]$x
                                }else{
                                    break
                                }
                            }
                            $TypeRefNamespace += $ObjNamespace                         
                           
                        }
                        $TypeRefMembers = @{$TypeRefNames = $TypeRefNamespace}
                    }

                    3 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 14), 1) | Out-Null}
                    # 4 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}
                    5 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}
                    # 6 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 10), 1) | Out-Null}
                    
                    # Method
                    7 {

                        # Create a hashtable to store all results
                        $MethodMembers = @{}
                        $MethodArray = @()
                        # Loop through the size of the table taken from the table size array entry
                        for($j=0;$j -lt $TableSizeArray[7]["Size"];$j++){

                            # Create a byte array of the structure size
                            $Method = [System.Byte[]]::CreateInstance([System.Byte], 14)

                            # Create a nested hashtable to store results 
                            $MethodMembers[$j] = @{}

                            # Read the $j structure
                            $FileReader.Read($Method, 0, 14) | Out-Null

                            # Set offset to name
                            $MethodMembers[$j]["Name"] = $Method[8..9]

                            # Reverse endian
                            [Array]::Reverse($MethodMembers[$j]["Name"])
                         
                            # Create a null object to store the char name array
                            $ObjName = $null

                            # Get the location of the string name in the heap and read 30 bytes worth of the array, storing valid char bytes into $objName
                            foreach($x in $StringHeap[([System.Convert]::ToInt64([SYstem.Convert]::ToHexString($MethodMembers[$j]["Name"]), 16))..([System.Convert]::ToInt64([SYstem.Convert]::ToHexString($MethodMembers[$j]["Name"]), 16) + 30)]){
                                if($x -ne 0){
                                    $ObjName += [char]$x
                                }else{
                                    break
                                }
                            }

                            # Store the name into $j name 
                            # $MethodMembers[$j]["Name"] = $ObjName 
                            $MethodArray += $ObjName                     
                        }
                    }

                    # 8 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 10), 1) | Out-Null}

                    # Param
                    9 {
                        # Create a hashtable to store all results
                        $ParamMembers = @{}
                        $ParamArray = @()
                        # Loop through the size of the table taken from the table size array entry
                        for($j=0;$j -lt $TableSizeArray[9]["Size"];$j++){

                            # Create a byte array of the structure size
                            $Param = [System.Byte[]]::CreateInstance([System.Byte], 6)

                            # Create a nested hashtable to store results 
                            $ParamMembers[$j] = @{}

                            # Read the $j structure
                            $FileReader.Read($Param, 0, 6) | Out-Null

                            # Set offset to name
                            $ParamMembers[$j]["Name"] = $Param[4..5]

                            # Reverse endian
                            [Array]::Reverse($ParamMembers[$j]["Name"])
                         
                            # Create a null object to store the char name array
                            $ObjName = $null

                            # Get the location of the string name in the heap and read 30 bytes worth of the array, storing valid char bytes into $objName
                            foreach($x in $StringHeap[([System.Convert]::ToInt64([SYstem.Convert]::ToHexString($ParamMembers[$j]["Name"]), 16))..([System.Convert]::ToInt64([SYstem.Convert]::ToHexString($ParamMembers[$j]["Name"]), 16) + 30)]){
                                if($x -ne 0){
                                    $ObjName += [char]$x
                                }else{
                                    break
                                }
                            }

                            # Store the name into $j name 
                            $ParamArray += $ObjName                      
                        }
                    }

                    10 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 4), 1) | Out-Null}

                    # MemberRef
                    11 {
                        # Create a hashtable to store all results
                        $MemberRefMembers = @{}
                        $MemberRefArray = @()
                        # Loop through the size of the table taken from the table size array entry
                        for($j=0;$j -lt $TableSizeArray[11]["Size"];$j++){

                            # Create a byte array of the structure size
                            $MemberRef = [System.Byte[]]::CreateInstance([System.Byte], 6)

                            # Create a nested hashtable to store results 
                            $MemberRefMembers[$j] = @{}

                            # Read the $j structure
                            $FileReader.Read($MemberRef, 0, 6) | Out-Null

                            # Set offset to name
                            $MemberRefMembers[$j]["Name"] = $MemberRef[2..3]

                            # Reverse endian
                            [Array]::Reverse($MemberRefMembers[$j]["Name"])
                         
                            # Create a null object to store the char name array
                            $ObjName = $null

                            # Get the location of the string name in the heap and read 30 bytes worth of the array, storing valid char bytes into $objName
                            foreach($x in $StringHeap[([System.Convert]::ToInt64([SYstem.Convert]::ToHexString($MemberRefMembers[$j]["Name"]), 16))..([System.Convert]::ToInt64([SYstem.Convert]::ToHexString($MemberRefMembers[$j]["Name"]), 16) + 30)]){
                                if($x -ne 0){
                                    $ObjName += [char]$x
                                }else{
                                    break
                                }
                            }

                            # Store the name into $j name 
                            $MemberRefArray += $ObjName                      
                        }
                    }

                    12 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}
                    13 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}
                    14 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 4), 1) | Out-Null}
                    15 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}
                    16 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 8), 1) | Out-Null}
                    17 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}
                    18 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 2), 1) | Out-Null}
                    19 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 4), 1) | Out-Null}
                    # 20 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 10), 1) | Out-Null}

                    # Event
                    21 {
                        # Create a hashtable to store all results
                        $EventMembers = @{}
                        $EventArray = @()
                        # Loop through the size of the table taken from the table size array entry
                        for($j=0;$j -lt $TableSizeArray[21]["Size"];$j++){

                            # Create a byte array of the structure size
                            $EventEntry = [System.Byte[]]::CreateInstance([System.Byte], 6)

                            # Create a nested hashtable to store results 
                            $EventMembers[$j] = @{}

                            # Read the $j structure
                            $FileReader.Read($EventEntry, 0, 6) | Out-Null

                            # Set offset to name
                            $EventMembers[$j]["Name"] = $EventEntry[2..3]

                            # Reverse endian
                            [Array]::Reverse($EventMembers[$j]["Name"])
                         
                            # Create a null object to store the char name array
                            $ObjName = $null

                            # Get the location of the string name in the heap and read 30 bytes worth of the array, storing valid char bytes into $objName
                            foreach($x in $StringHeap[([System.Convert]::ToInt64([SYstem.Convert]::ToHexString($EventMembers[$j]["Name"]), 16))..([System.Convert]::ToInt64([SYstem.Convert]::ToHexString($EventMembers[$j]["Name"]), 16) + 30)]){
                                if($x -ne 0){
                                    $ObjName += [char]$x
                                }else{
                                    break
                                }
                            }

                            # Store the name into $j name 
                            $EventArray += $ObjName                 
                        }
                    }

                    22 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 4), 1) | Out-Null}
                    # 23 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 10), 1) | Out-Null}
                    24 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}
                    25 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}
                    26 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}

                    # ModuleRef
                    27 {
                        # Create a hashtable to store all results
                        $ModuleRefMembers = @{}
                        $ModuleArray = @()
                        # Loop through the size of the table taken from the table size array entry
                        for($j=0;$j -lt $TableSizeArray[27]["Size"];$j++){

                            # Create a byte array of the structure size
                            $ModuleRef = [System.Byte[]]::CreateInstance([System.Byte], 2)

                            # Create a nested hashtable to store results 
                            $ModuleRefMembers[$j] = @{}

                            # Read the $j structure
                            $FileReader.Read($ModuleRef, 0, 2) | Out-Null

                            # Set offset to name
                            $ModuleRefMembers[$j]["Name"] = $ModuleRef[0..1]

                            # Reverse endian
                            [Array]::Reverse($ModuleRefMembers[$j]["Name"])
                         
                            # Create a null object to store the char name array
                            $ObjName = $null

                            # Get the location of the string name in the heap and read 30 bytes worth of the array, storing valid char bytes into $objName
                            foreach($x in $StringHeap[([System.Convert]::ToInt64([SYstem.Convert]::ToHexString($ModuleRefMembers[$j]["Name"]), 16))..([System.Convert]::ToInt64([SYstem.Convert]::ToHexString($ModuleRefMembers[$j]["Name"]), 16) + 30)]){
                                if($x -ne 0){
                                    $ObjName += [char]$x
                                }else{
                                    break
                                }
                            }

                            # Store the name into $j name 
                            $ModuleArray += $ObjName                    
                        }
                    }

                    28 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 2), 1) | Out-Null}

                    # ImplMap
                    29 {
                        # Create a hashtable to store all results
                        $ImplMapMembers = @{}
                        $ImplArray =@()
                        # Loop through the size of the table taken from the table size array entry
                        for($j=0;$j -lt $TableSizeArray[29]["Size"];$j++){

                            # Create a byte array of the structure size
                            $ImplMap = [System.Byte[]]::CreateInstance([System.Byte], 8)

                            # Create a nested hashtable to store results 
                            $ImplMapMembers[$j] = @{}

                            # Read the $j structure
                            $FileReader.Read($ImplMap, 0, 8) | Out-Null

                            # Set offset to name
                            $ImplMapMembers[$j]["Name"] = $ImplMap[4..5]

                            # Reverse endian
                            [Array]::Reverse($ImplMapMembers[$j]["Name"])
                         
                            # Create a null object to store the char name array
                            $ObjName = $null

                            # Get the location of the string name in the heap and read 30 bytes worth of the array, storing valid char bytes into $objName
                            foreach($x in $StringHeap[([System.Convert]::ToInt64([SYstem.Convert]::ToHexString($ImplMapMembers[$j]["Name"]), 16))..([System.Convert]::ToInt64([SYstem.Convert]::ToHexString($ImplMapMembers[$j]["Name"]), 16) + 30)]){
                                if($x -ne 0){
                                    $ObjName += [char]$x
                                }else{
                                    break
                                }
                            }

                            # Store the name into $j name 
                            $ImplArray += $ObjName                    
                        }
                    }

                    30 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}
                    # 31 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 10), 1) | Out-Null}
                    # 32 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 10), 1) | Out-Null}
                    33 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 22), 1) | Out-Null}
                    34 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 4), 1) | Out-Null}
                    35 {$FileReader.Seek(($TableSizeArray[$i]["Size"] * 12), 1) | Out-Null}

                    # AssemblyRef
                    36 {
                        # Create a hashtable to store all results
                        $AssemblyRefMembers = @{}
                        $AssemblyArray = @()
                        # Loop through the size of the table taken from the table size array entry
                        for($j=0;$j -lt $TableSizeArray[36]["Size"];$j++){

                            # Create a byte array of the structure size
                            $AssemblyRef = [System.Byte[]]::CreateInstance([System.Byte], 20)

                            # Create a nested hashtable to store results 
                            $AssemblyRefMembers[$j] = @{}

                            # Read the $j structure
                            $FileReader.Read($AssemblyRef, 0, 20) | Out-Null

                            # Set offset to name
                            $AssemblyRefMembers[$j]["Name"] = $AssemblyRef[14..15]

                            # Reverse endian
                            [Array]::Reverse($AssemblyRefMembers[$j]["Name"])
                         
                            # Create a null object to store the char name array
                            $ObjName = $null

                            # Get the location of the string name in the heap and read 30 bytes worth of the array, storing valid char bytes into $objName
                            foreach($x in $StringHeap[([System.Convert]::ToInt64([SYstem.Convert]::ToHexString($AssemblyRefMembers[$j]["Name"]), 16))..([System.Convert]::ToInt64([SYstem.Convert]::ToHexString($AssemblyRefMembers[$j]["Name"]), 16) + 30)]){
                                if($x -ne 0){
                                    $ObjName += [char]$x
                                }else{
                                    break
                                }
                            }

                            # Store the name into $j name 
                            $AssemblyArray += $ObjName                  
                        }
                    }

                    # Default skip bytes 
                    # default {Write-Host "You should not see this"}
                }
            }


            # Close file
            $FileReader.Dispose() 
            $FileReader.Close()


            # Convert to strings for operations and printing
            $OptionalHeaders = [System.Convert]::ToHexString($OptionalHeaders)
            $OptionalHeaders = $OptionalHeaders -replace '..(?!$)','$0 '
        }

        # Get time stamp from COFF header
        [byte[]]$TimeStamp = $COFFHeader[8..11] 
        [Array]::Reverse($TimeStamp)
        [string]$Timestamp = (([System.DateTimeOffset]::FromUnixTimeSeconds([System.Convert]::ToInt64([System.Convert]::ToHexString($TimeStamp),16))).DateTime).ToString("s")

        # Convert to strings for operations and printing
        $COFFHeader = [System.Convert]::ToHexString($COFFHeader)
        $COFFHeader = $COFFHeader -replace '..(?!$)','$0 '

        $ImportTable = [System.Convert]::ToHexString($ImportTable)
        $ImportTable = $ImportTable -replace '..(?!$)','$0 '

        # $SectionsTableStrings[$i]["PointerToRawData"] = $SectionsTableStrings[$i]["PointerToRawData"] -replace '..(?!$)','$0 '

        # Operate on strings and print results
        switch -Wildcard ($COFFHeader){
            "50 45 00 00 4C*" {$Bit = "32-Bit";break}
            "50 45 00 00 64*" {$Bit = "64-Bit";break}
            default {$Bit = "Unable to determine type from COFF header"; break}
        }
        $SectionsNames = @()
        $SectionsOffsets =@()
        for($i=0;$i -lt $Sections;$i++){
            $SectionsTableStrings[$i]["VirtualAddress"] = $SectionsTableStrings[$i]["VirtualAddress"] -replace '..(?!$)','$0 '
            $SectionsNames += $SectionsTableStrings[$i]["Name"]
            $SectionsOffsets +=$SectionsTableStrings[$i]["VirtualAddress"]
        }
        $StreamNames = @()
        $StreamOffsets = @()
        for($i=0;$i -lt $MetaDataStreams;$i++){
            $MetaDataStream[$i]["Offset"] = [System.Convert]::ToHexString($MetaDataStream[$i]["Offset"]) -replace '..(?!$)','$0 '
            $StreamNames += $MetaDataStream[$i]["Name"]
            $StreamOffsets += $MetaDataStream[$i]["Offset"]
            # Write-Host "Size:" $MetaDataStream[$i]["Size"]
        }

        # Object
        $Results = New-Object PSObject -Property $([ordered]@{
            FileName = $file
            Type = "$Bit" + " $PEType"
            TimeStamp = $TimeStamp
            Checksum = $CheckSum
            SectionNames = $SectionsNames
            SectionOffsets = $SectionsOffsets
            MetadataOffset = $MetaDataSeek.ToString("X8") -replace '..(?!$)','$0 '
            Streams = $StreamNames
            StreamsOffset = $StreamOffsets
            ImportTable = $ImportLookupName + " $ImportDLLName"
            TypeRefNames = $TypeRefNames
            TypeRefNamespace = $TypeRefNamespace
            Methods = $MethodArray
            Params = $ParamArray
            MemberRef = $MemberRefArray
            Events = $EventArray
            ModuleRef = $ModuleArray
            Imports = $ImplArray
            AssemblyRef = $AssemblyArray
        })
        if($PrintAll){
            $pageout = @"
FileName
         $($Results.FileName)
Type
         $($Results.Type)
TimeStamp
         $($Results.TimeStamp)
Checksum
         $($Results.Checksum)
SectionNames
         $($Results | Select -Expand SectionNames  | foreach {write-output "$_`n`t"})
SectionOffsets
         $($Results | Select -Expand SectionOffsets  | foreach {write-output "$_`n`t"})
MetadataOffset
         $($Results | Select -Expand MetadataOffset  | foreach {write-output "$_`n`t"})
Streams
         $($Results | Select -Expand Streams  | foreach {write-output "$_`n`t"})
StreamsOffset
         $($Results | Select -Expand StreamsOffset  | foreach {write-output "$_`n`t"})
ImportTable
         $($Results | Select -Expand ImportTable  | foreach {write-output "$_`n`t"})
TypeRefNames
         $($Results | Select -Expand TypeRefNames  | foreach {write-output "$_`n`t"})
TypeRefNamespace
         $($Results | Select -Expand TypeRefNamespace  | foreach {write-output "$_`n`t"})
Methods
         $($Results | Select -Expand Methods  | foreach {write-output "$_`n`t"})
Params
         $($Results | Select -Expand Params  | foreach {write-output "$_`n`t"})
MemberRef
         $($Results | Select -Expand MemberRef  | foreach {write-output "$_`n`t"})
Events
         $($Results | Select -Expand Events  | foreach {write-output "$_`n`t"})
ModuleRef
         $($Results | Select -Expand ModuleRef | foreach {write-output "$_`n`t"})
Imports
         $($Results | Select -Expand Imports  | foreach {write-output "$_`n`t"})
AssemblyRef
         $($Results | Select -Expand AssemblyRef  | foreach {write-output "$_`n`t"})
"@
        write-output $Pageout
        }else{
            $Results
        }
    }
    catch {
        $FileReader.Dispose() 
        $FileReader.Close()
        $error[0]
    }finally{
        # If interrupt
        $FileReader.Dispose() 
        $FileReader.Close()
    }
   }    

}

function Invoke-FileAnalysis([Parameter(Mandatory=$true,ValueFromPipeline=$True,HelpMessage="Enter one or more file paths separated by commas")] [string]$File, [parameter(Mandatory=$false,HelpMessage="Display strings?")] [Switch]$Strings , [Parameter(Mandatory=$false,ValueFromPipeline=$false,HelpMessage="VirusTotal API Key")] [string] $APIKey,[Parameter(Mandatory=$false,ValueFromPipeline=$false,HelpMessage="Print all imports")] [switch]$PrintAll ){
<#
    .SYNOPSIS
        Invoke-FileAnalysis returns Get-FileType, Get-VirusTotalAnalysis, and optionally Get-Strings for any given file or list of files.

    .EXAMPLE
        Invoke-FileAnalysis "filepath1","filepath2","filepath3" -Strings

        This example returns all content for each file submitted.
#>
    foreach($x in $File){
        try {
            if(-Not ([System.IO.File]::Exists($x))){
                throw "File does not exist"
            }
            # Send to FileType
            $filetype = Get-FileType $x
            Write-Output "File Type Analysis`n"
            $filetype
            # Send to PE Analysis if it's a PE file
            if($filetype.Signature -match "4D 5A 90 00"){
                Write-Output "PE File Analysis`n"
                if($PrintAll){
                    Invoke-PEAnalysis $x -PrintAll
                }else{
                    Invoke-PEAnalysis $x
                }

            }
            # Send to VirusTotal
            if($APIKey){
                Write-Output "VirusTotal Analysis `n"
                Get-VirusTotalAnalysis $x $APIKey
            }else{
                Write-Output "VirusTotal Analysis `n"
                Write-Host "No VirusTotal API key specified, using saved credentials`n"
                Get-VirusTotalAnalysis $x
            }
            # Send to Strings
            if($Strings){
                Write-Output "Strings"
                Get-Strings $x
            }
        }
        catch {
            $error[0]
        }
    }
}


Export-ModuleMember -Function Get-FileType, Get-Strings, Get-VirusTotalAnalysis, Invoke-FileAnalysis, Invoke-PEAnalysis