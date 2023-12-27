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
Get-VirusTotalAnalysis X
    Submits file information to VT for analysis **Based on SHA256 hashes**.
Get-CompressedFiles **Probably not worth it**
    Binwalk extraction functionality.
Invoke-FileAnalysis X
    Create a report on analysis modules. Supports saving to word documents. ** Will add once a template is decided. For now, redirect output with *> or Out-String.**





#>


function Get-FileType([Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Enter one or more file names separated by commas")] [string[]] $Files){
<#
    .SYNOPSIS
        Get-FileType uses the first 10 bytes of a given file or series of files to determine the file type. Various file signatures are defined in the code, and more can be added following the format. 

    .EXAMPLE 
        Get-FileType "filepath1","filepath2","filepath3"

        This example submits multiple files for analysis.
#>
    function Results([string]$Type, [string]$FilePath, [string]$FileHash="bullshit") {
        $Results = [PSCustomObject]@{
            Signatures = @{
                "4D 5A"=[Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="EXE,DLL,MUI,SYS,SCR,CPL,OCX,AX,IEC,IME,RS,TSP,FON,EFI"
                    "Description"="DOS MZ executable and its descendants (including NE and PE)"
                };
                "23 21"=[Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"=""
                    "Description"="Script or data to be passed to the program following the shebang (#!)"
                };
                "FF D8"=[Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="JPG,JPEG"
                    "Description"="JPEG/JFIF image file"
                };
                "89 50 4E 47 0D 0A 1A 0A"=[Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="PNG"
                    "Description"="PNG image file"
                };
                "49 44 33"=[Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="MP3"
                    "Description"="MP3 audio file with ID3 tag"
                };
                "1F 8B 08"=[Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="GZ,TAR,TAR.GZ"
                    "Description"="GZIP compressed TAR archive"
                };
                "25 50 44 46"=[Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="PDF"
                    "Description"="Adobe PDF document"
                };
                "50 4B 03 04"=[Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="ZIP"
                    "Description"="ZIP archive"
                };
                "D0 CF 11 E0 A1 B1 1A E1"=[Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="DOC"
                    "Description"="Microsoft Word Document (97-2003)"
                };
                "50 4B 03 04 14 00"=[Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="DOCX, PPTX"
                    "Description"="Microsoft Word Document (2007 and later)"
                };
                "FF FB"=[Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="OGG"
                    "Description"="Ogg Vorbis audio file"
                };
                "1A 45 DF A3"=[Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="COM"
                    "Description"="DOS executable file"
                };
                "CA FE BA BE"=[Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="CLASS"
                    "Description"="Java class file"
                };
                "72 72 65 3C"=[Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="JAR"
                    "Description"="Java Archive file"
                };
                "37 7A BC AF 27 1C"=[Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="7Z"
                    "Description"="7-Zip archive file"
                };
                "52 49 46 46"=[Ordered]@{
                    "FileName"=$FilePath
                    "FileHash"=$FileHash
                    "Signature"=$Type
                    "Extensions"="AVI"
                    "Description"="Audio Video Interleave (AVI) file"
                };
                "0A 0D 0D 0A 44 00 00 00 4D 3C"=[Ordered]@{
                    "FilenName"=$FilePath
                    "FileHash"=$FilePath
                    "Signature"=$Type
                    "Extensions"="PCAP"
                    "Description"="WireShark PCAP file"
                };
                "Undetermined"=[Ordered]@{
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
            throw "File does not exist"
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
        # Write-Error -Message "File does not exist or is a directory." 
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
                throw "File does not exist"
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
            Write-Error -Message "File does not exist or is a directory."
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
                }elseif($Content.data.attributes.last_analysis_stats.malicious -ge 1 -Or $Content.data.attributes.last_analysis_stats.Suspicious -ge 1){
                    $Determination = "Suspicious"
                }else{
                    $Determination = "Harmless"
                }
                Write-Host "File:"$Files
                Write-Host "Determination:"$Determination
                Write-Host "`nDetection stats:" 
                $Content.data.attributes.last_analysis_stats
                Write-Host "`nLink: " -NoNewline 
                $Content.data.links.self
                Write-Host
            }
        }
        catch {
            Write-Error -Message "File does not exist or is a directory."
        }
    }
}

function Invoke-FileAnalysis([Parameter(Mandatory=$true,ValueFromPipeline=$True,HelpMessage="Enter one or more file paths separated by commas")] [string]$File, [parameter(Mandatory=$false,HelpMessage="Display strings?")] [Switch]$Strings , [Parameter(Mandatory=$false,ValueFromPipeline=$false,HelpMessage="VirusTotal API Key")] [string] $APIKey){
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
            Get-FileType $x
            # Send to VirusTotal
            if($APIKey){
                Get-VirusTotalAnalysis $x $APIKey
            }else{
                Write-Host "No VirusTotal API key specified, using saved credentials`n"
                Get-VirusTotalAnalysis $x
            }
            # Send to Strings
            if($Strings){
                Write-Host "Strings"
                Get-Strings $x
            }
        }
        catch {
            Write-Error "File does not exist or is a directory."
        }
    }
}
Export-ModuleMember -Function Get-FileType, Get-Strings, Get-VirusTotalAnalysis, Invoke-FileAnalysis