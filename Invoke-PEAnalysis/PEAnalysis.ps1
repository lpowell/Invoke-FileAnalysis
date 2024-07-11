# Extra special PowerShell 5.1 version for distribution
# Invoke-PEAnalysis
<# Design 

Flow
Function #1 - File validation
- File is located (context or full path)
- File is validated as a PE file and the version is retrieved (x86 vs x64)

Function #2 - Packing tester
- Checks if the PE file is packed
- Attempts to auto unpack certain packers
    - Prompt

Function #3 - Ripper
- Opens and parses the PE file based on passed version
- Returns complete tables and various data

Function #4 - Reputation Check (Optional)
- Performs reputation checks with VirusTotal on file hash

Function #5 - Prettifier 
- Generate reports, log to screen, make visuals 


#>
# There are no errors to be found here...
# $global:ErrorActionPreference="SilentlyContinue"

# Log function 
function Write-Log([string]$LogMessage, $Level)
{
    $MessageTime = [System.DateTime]::UTCNow 
    switch($LogLevel){
        3 {
            "$MessageTime`t$LogMessage" | Out-File -FilePath $LogFile -Append
            Write-Verbose "$MessageTime`t$LogMessage"
        }

        2 {
            if($Level -le 2){
                "$MessageTime`t$LogMessage" | Out-File -FilePath $LogFile -Append
                Write-Verbose "$MessageTime`t$LogMessage"
            }
        }

        default {
            if($Level -eq 1){
                "$MessageTime`t$LogMessage" | Out-File -FilePath $LogFile -Append
                Write-Verbose "$MessageTime`t$LogMessage"
            }
        }
    }
}

# Main module 
Function Invoke-PEAnalysis(){
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$true)]$Path,
        [Parameter(Mandatory=$False)]$LogFile="$env:USERPROFILE\Documents\PEAnalysis\PEAnalysis.log",
        [Parameter(Mandatory=$False)]$Style,
        [Parameter(Mandatory=$false)]$APIKey,
        [Parameter(Mandatory=$false)][Switch]$SkipEntropyCheck,
        [Parameter(Mandatory=$false)][Switch]$SkipVirusTotalCheck
    )
    BEGIN{
        $stopwatch = [System.Diagnostics.Stopwatch]::new()
        $Stopwatch.Start()
    }PROCESS{
        # Create log directory if it doesn't exist
        if((-Not ([System.IO.File]::Exists($LogFile)))){
            # IDK why I did this way. It's kinda fun tho. 
            New-Item -Path ([string]::Join("\",($LogFile.split("\")[0..$($LogFile.split("\").Length - 3)]))) -Name $LogFile.split("\")[4] -ItemType "directory"
        }

        # Log start of execution
        Write-Log "Initializing Module" 1

        # Validate file as a PE
        # Passes Path ref to allow validation function to adjust path as needed 
        # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_ref?view=powershell-7.4
        if(FileValidation ([ref]$Path)){
            Write-Log "PE File Validated: $Path" 1
        }else{
            Write-Error "File is not a valid PE file or is not formatted correctly. Please see any additional errors for more context."
            return
        }
        
        # Get the results of the rep check 
        if(!$SkipVirusTotalCheck){
            $Rep = RepCheck
        }else{
            # Feeling lazy at the end
            $Rep = [PSCustomObject][Ordered]@{
                File = "API Key must be supplied"
                Determination = "API Key must be supplied"
                Hash = "API Key must be supplied"
                Malicious = "API Key must be supplied"
                Suspicious = "API Key must be supplied"
                Harmless = "API Key must be supplied"
                Raw = "API Key must be supplied"
                Link = "API Key must be supplied"
            }
        }
        
        # $rep = "normally there would be something here"

        # Check if an executable is packed
        if(-Not $SkipEntropyCheck){
            If(IsPacked){
                Write-Log "File may be packed" 1
                $global:Packed = $true
            }
        }

        $Analysis = Ripper

        # Operational Time
        $stopwatch.Stop()
        Write-Log "Total execution time: $($stopwatch.Elapsed.TotalSeconds)" 1
        # Rip the file and pass the returned obj to Output for formatting
        Output $Analysis $Rep
    }END{
        # Time was here until output modes were made. Now it's empty :(
    }

}

# File validation function
Function FileValidation([Parameter(Mandatory=$True)]$Path){

    try {
        # Test if file exists
        if((-Not ([System.IO.File]::Exists($Path.Value))) -And (-Not ([System.IO.File]::Exists("$(pwd)$($Path.Value)")))){
            throw "File does not exist: $Path"
        }
        if([System.IO.File]::Exists("$(pwd)$($Path.Value)")){
            $Path.Value = "$(pwd)$($Path.Value)"
        }

        # Test for PE header
        $ByteArray = [System.Byte[]]::CreateInstance([System.Byte], 10) 
        $FileReader = New-Object System.IO.FileStream($Path.Value, "Open")
        $FileReader.Read($ByteArray, 0, 10) | Out-Null
        $ByteArray = [CustomConvert]::ToHexString($ByteArray)
        $ByteArray = $ByteArray -replace '..(?!$)','$0 '
        $FileReader.Dispose()

        # Return the bool status of the operation
        return ($ByteArray -match "4D 5A")
    }
    catch {
        # Log contextual errors 
        Write-Log ($_.ScriptStackTrace).ToString() 1
        Write-Log ($_.Exception).ToString() 1
        Write-Log ($_.FullyQualifiedErrorId).ToString() 1
        return $false
    }
}


Function IsPacked(){
    # Test for packing by evaluating file entropy - Will build sig detectors into Ripper maybe
    # I stole this from https://github.com/TonyPhipps/Powershell/blob/master/Get-Entropy.psm1 
    # And this https://cocomelonc.github.io/malware/2022/11/05/malware-analysis-6.html
    # I can't do math on my own :(
    begin{
        $stopwatch = [System.Diagnostics.Stopwatch]::new()
        $Stopwatch.Start()
    }process{
        Write-Log "Checking for packing via entropy" 1
        
        # Read all bytes of file into a byte array 
        $file = [System.IO.File]::ReadAllBytes("$Path")

        # Group the byte array by value
        $group = $file | Group-Object

        # Set entropy to 0
        $global:entropy = 0.0

        # Shannon Entropy 
        Foreach($x in $group){
            $p = $x.Count / $file.Length
            $global:entropy -= $p * [Math]::Log($p,2)
        }
        Clear-Variable -Name file
        return ($entropy -ge 6)
    }end{
        $stopwatch.Stop()
        Write-Log "Entropy: $entropy" 1
        Write-Log "Entropy check time: $($stopwatch.Elapsed.TotalSeconds)" 1
    }
}

# Dumb .Net framework stuff
Add-Type -TypeDefinition @"
using System;

public static class CustomConvert {
    public static string ToHexString(byte[] bytes) {
        return BitConverter.ToString(bytes).Replace("-", "");
    }
}
"@

Function Ripper(){
    try{
    Write-Log "Beginning PE analysis" 1
    # Open File
    $File = New-Object System.IO.FileStream($Path, "Open")
    
    # Create COFF header array
    $CoffHeader = [System.Byte[]]::CreateInstance([System.Byte], 24)
    
    # Create temp holding array
    $CFFOFFSET = [System.Byte[]]::CreateInstance([System.Byte], 2)

    # Read 60 bytes of MS-DOS STUB to find offset of COFF header
    $File.Seek(60,0) | Out-Null
    $file.Read($CFFOFFSET,0,2) | Out-Null
    [Array]::Reverse($CFFOFFSET)
    $file.Seek(([System.Convert]::ToInt64([CustomConvert]::ToHexString($CFFOFFSET),16) + 4),0) | Out-Null

    # Read COFF header 
    $File.Read($CoffHeader, 0, 20) | Out-Null
    # [CustomConvert]::ToHexString($CoffHeader)

    # Save the Optional Header size
    $SizeOfOptionalHeader = $COFFHeader[16..17]
    [Array]::Reverse($SizeOfOptionalHeader)
    # [CustomConvert]::ToHexString($SizeOfOptionalHeader)
    # $COFFHeader[20..21]
    $SizeOfOptionalHeader = [System.Convert]::ToInt64([CustomConvert]::ToHexString($SizeOfOptionalHeader),16)
        if($SizeOfOptionalHeader -gt 0){     
            # Build optional header array based on size
            $OptionalHeaders = [System.Byte[]]::CreateInstance([System.Byte], $SizeOfOptionalHeader)
        }else{
            Write-Log "Optional Headers could not be found: $SizeOfOptionalHeader" 1
            Write-Log "Cancelling analysis" 1
            # Close file
            $File.Dispose() | out-Null
            $File.Close() | Out-Null
            return 
        }
    
        # Read optional header [Sequential X bytes after COFF header]
        $File.Read($OptionalHeaders, 0, $SizeOfOptionalHeader) | Out-Null
    
        # Get Sections
        # Assumes 1 byte of sections 
        # I should choose not to be lazy and actually support the standard 2-byte value, but meh
        $Sections = $COFFHeader[2]
    
        # Section Tables
        $SectionsTableStrings = @{}
        for($i=0;$i -lt $Sections;$i++){
            $SectionsTable = [System.Byte[]]::CreateInstance([System.Byte], 40) 
            $File.Read($SectionsTable, 0, 40) | Out-Null
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
            $SectionsTableStrings[$i]["VirtualAddress"] = [CustomConvert]::ToHexString($SectionsTableStrings[$i]["VirtualAddress"])
            [Array]::Reverse($SectionsTableStrings[$i]["PointerToRawData"])
            $SectionsTableStrings[$i]["PointerToRawData"] = [CustomConvert]::ToHexString($SectionsTableStrings[$i]["PointerToRawData"])
    
            
            # Get Names
            $SectionNames = $null
            foreach($x in $SectionsTableStrings[$i]['Name']){
                $SectionNames += [char]$x
            }
            $SectionsTableStrings[$i]["Name"] = $SectionNames -join ''
            if($SectionsTableStrings[$i]["Name"] -match "UPX"){
                Write-Log "UPX PACKING DETECTED: $($SectionsTableStrings[$i]["Name"])" 1
                $Packed = $true
            }

            # # REMOVE
            # Write-Host "Name:$($SectionsTableStrings[$i]["Name"])"
            # Write-Host "Address: $($SectionsTableStrings[$i]["VirtualAddress"])"

        }
    
        # Operate on raw arrays
    
        # Optional Header section
        # Determine PE type from Optional Header Magic number
        Write-Log "Testing PE file type" 1
        $OptionalMagic = $OptionalHeaders[0..1]
        [array]::Reverse($OptionalMagic)
        $OptionalMagic = [CustomConvert]::ToHexString($OptionalMagic)
        switch ($OptionalMagic) {
            '010B' { $PEType = "PE32";break }
            '020B' { $PEType = "PE32+";break}
            '0107' { $PEType = "ROM";break}
            Default {
                Write-Log "Unable to determine PE type. Optional Header Magic: $OptionalMagic" 1
                if(-Not $Packed){
                    Write-Log "File is not detected as packed via entropy. However, PE file type cannot be determined via Optional Header Magic Number. File is likely packed." 1
                    Write-Log "Assuming file is PE32 type" 1
                    $PEType = "PE32"
                }else{
                    Write-Log "File detected as packed via entropy." 1
                    Write-Log "Assuming file is PE32 type" 1
                    $PEType = "PE32"
                }
        }
        }
        Write-Log "PE Type: $PEType" 1
        # Get size of .text section
        $TextSize = $OptionalHeaders[4..7]
        [Array]::Reverse($TextSize)
        $TextSize = [System.Convert]::ToInt64([CustomConvert]::ToHexString($TextSize),16)

        # Get entry points
        $AddressOfEntryPoint = $OptionalHeaders[16..19]
        [array]::Reverse($AddressOfEntryPoint)
        $AddressOfEntryPoint = [CustomConvert]::ToHexString($AddressOfEntryPoint)
        $AddressOfEntryPoint = $AddressOfEntryPoint -replace '..(?!$)','$0 '
        $BaseOfCode = $OptionalHeaders[20..23]

        # Break between PE32 and PE32+ formats
        if($PEType -eq "PE32"){
            Write-Log "Beginning PE32 analysis" 1
            # Base of Data is specific to PE32 files - Not present in PE32+ (64-bit)
            # https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
            $BaseOfData = $OptionalHeaders[24..27]

            # Get entry point of first byte
            $ImageBase = $OptionalHeaders[28..31]
            [Array]::Reverse($ImageBase)
            $ImageBase = [CustomConvert]::ToHexString($ImageBase)
            $ImageBase = $ImageBase -replace '..(?!$)','$0 '

            # Section and File alignment
            $SectionAlignment = $OptionalHeaders[32..25]
            $FileAlignment = $OptionalHeaders[36..39]

            # Size of Image
            $SizeOfImage = $OptionalHeaders[56..59]
            [array]::Reverse($SizeOfImage)
            $SizeOfImage = [System.Convert]::ToInt64([CustomConvert]::ToHexString($SizeOfImage),16)

            # Size of Headers
            $SizeOfHeaders = $OptionalHeaders[60..63]
            [array]::Reverse($SizeOfHeaders)
            $SizeOfHeaders = [System.Convert]::ToInt64([CustomConvert]::ToHexString($SizeOfHeaders),16)

            # CheckSum
            $CheckSum = $OptionalHeaders[64..67]
            [Array]::Reverse($CheckSum)
            $CheckSum = [CustomConvert]::ToHexString($CheckSum)
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
            $IAT = [CustomConvert]::ToHexString($IAT)
            $IAT = $IAT -replace '..(?!$)','$0 '

            # CLR Runtime Header = .NET Header 
            # First DWORD is offset [4..7], second is size [0..3]
            $CLRRuntimeHeader = $OptionalHeaders[208..215]
            [Array]::Reverse($CLRRuntimeHeader)

            # # REMOVE
            # Write-Host "OPTIONAL HEADERS $([CustomConvert]::ToHexString($OptionalHeaders))"


        }elseif($PEType -eq "PE32+"){
            Write-Log "Beginning PE32+ Analysis" 1
            # Get entry point of first byte
            $ImageBase = $OptionalHeaders[24..31]
            [Array]::Reverse($ImageBase)
            $ImageBase = [CustomConvert]::ToHexString($ImageBase)
            $ImageBase = $ImageBase -replace '..(?!$)','$0 '

            # Section and File alignment
            $SectionAlignment = $OptionalHeaders[32..25]
            $FileAlignment = $OptionalHeaders[36..39]

            # Size of Image
            $SizeOfImage = $OptionalHeaders[56..59]
            [array]::Reverse($SizeOfImage)
            $SizeOfImage = [System.Convert]::ToInt64([CustomConvert]::ToHexString($SizeOfImage),16)

            # Size of Headers
            $SizeOfHeaders = $OptionalHeaders[60..63]
            [array]::Reverse($SizeOfHeaders)
            $SizeOfHeaders = [System.Convert]::ToInt64([CustomConvert]::ToHexString($SizeOfHeaders),16)

            # CheckSum
            $CheckSum = $OptionalHeaders[64..67]
            [Array]::Reverse($CheckSum)
            $CheckSum = [CustomConvert]::ToHexString($CheckSum)
            $CheckSum = $CheckSum -replace '..(?!$)','$0 '

            # Export Table
            $ExportTable = $OptionalHeaders[112..119]
            
            # Import Table
            $ImportTable = $OptionalHeaders[120..127]
            [array]::Reverse($ImportTable)
            

            # Resource Table
            $ResourceTable = $OptionalHeaders[128..135]

            # Exception Table
            $ExceptionTable = $OptionalHeaders[136..143]

            # IAT
            $IAT = $OptionalHeaders[208..215]
            [array]::Reverse($IAT)
            $IAT = [CustomConvert]::ToHexString($IAT)
            $IAT = $IAT -replace '..(?!$)','$0 '

            # CLR Runtime Header = .NET Header 
            # First DWORD is offset [4..7], second is size [0..3]
            $CLRRuntimeHeader = $OptionalHeaders[224..231]
            [Array]::Reverse($CLRRuntimeHeader)

            # # REMOVE
            # Write-Host "OPTIONAL HEADERS $([CustomConvert]::ToHexString($OptionalHeaders))"

            
        }
        Write-Log "Parsed PE file type specifc sections" 1
        Write-Log "Getting imports" 1
        # Get Import Directory Table
        # Find what section IDT is in
        for($i=0;$i -lt $Sections;$i++){
            # Virtual Address -lt Import Table address && Virtual Address + Virtual Size -gt Import Table Address
            # Section Start <----> Import Table <----> End of Section
            # If the section starts with the import table
            if([System.Convert]::ToInt64($SectionsTableStrings[$i]["VirtualAddress"], 16) -lt [System.Convert]::ToInt64([CustomConvert]::ToHexString($ImportTable[4..7]), 16) -And ([System.Convert]::ToInt64($SectionsTableStrings[$i]["VirtualAddress"], 16) + [System.Convert]::ToInt64([CustomConvert]::ToHexString($SectionsTableStrings[$i]["VirtualSize"]), 16)) -gt [System.Convert]::ToInt64([CustomConvert]::ToHexString($ImportTable[4..7]), 16)){
                # Write-Host "IDT is in:"$SectionsTableStrings[$i]["Name"]
                $IDTOffset = [Math]::ABS([System.Convert]::ToInt64([CustomConvert]::ToHexString($ImportTable[4..7]), 16) - [System.Convert]::ToInt64($SectionsTableStrings[$i]["VirtualAddress"], 16))
                $IDTSeek = $IDTOffset + [System.Convert]::ToInt64($SectionsTableStrings[$i]["PointerToRawData"], 16)

                # # REMOVE
                # Write-Host "IDT OFFSET $($IDTOffset)"
                # Write-Host "IDT SEEK $($IDTSeek)"
                # Write-Host "IDT RVA $($SectionsTableStrings[$i]["VirtualAddress"])"

                # Set the found section for use with IDT imports
                $IDTSection = $i
            }elseif((([System.Convert]::ToInt64($SectionsTableStrings[$i]["VirtualAddress"], 16))-eq([System.Convert]::ToInt64([CustomConvert]::ToHexString($ImportTable[4..7]), 16)))-And ([System.Convert]::ToInt64($SectionsTableStrings[$i]["VirtualAddress"], 16) + [System.Convert]::ToInt64([CustomConvert]::ToHexString($SectionsTableStrings[$i]["VirtualSize"]), 16)) -gt [System.Convert]::ToInt64([CustomConvert]::ToHexString($ImportTable[4..7]), 16)){
                # Write-Host "IDT is in:"$SectionsTableStrings[$i]["Name"]
                $IDTOffset = [Math]::ABS([System.Convert]::ToInt64([CustomConvert]::ToHexString($ImportTable[4..7]), 16) - [System.Convert]::ToInt64($SectionsTableStrings[$i]["VirtualAddress"], 16))
                $IDTSeek = $IDTOffset + [System.Convert]::ToInt64($SectionsTableStrings[$i]["PointerToRawData"], 16)

                # REMOVE
                # Write-Host "IDT SIZE $([CustomConvert]::ToHexString($ImportTable[4..7]))"
                # Write-Host "IDT OFFSET $($IDTOffset)"
                # Write-Host "IDT SEEK $($IDTSeek)"
                # Write-Host "IDT RVA $($SectionsTableStrings[$i]["VirtualAddress"])"

                # Set the found section for use with IDT imports
                $IDTSection = $i
            }
        }
        # Parse IDT for DLLs
        # 20 null bytes after first IDT
        # Hash table to store results
        # Get section from sectiontable to replace 0 in sectiontable hashtable
        $ImportDirectoryTable = @{}
        $ImportDLLNameArray= @()
            for($i=0;;$i++){
                # Seek offset
                $File.Seek($IDTSeek, 0) | Out-Null
                $IDTArray = [System.Byte[]]::CreateInstance([System.Byte], 20) 
                $File.Read($IDTArray, 0, 20) | Out-Null

                # # REMOVE
                # Write-Host "IDTARRAY $([CustomConvert]::ToHexString($IDTARRAY))"
                
                # If the NameRVA is empty, exit loop
                if([System.Convert]::ToInt64([CustomConvert]::ToHexString($IDTArray[12..15]), 16) -eq 0){
                    break
                }

                # Initialize $i as a hashtable
                $ImportDirectoryTable[$i] = @{}

                # Read DLL Name RVA
                $ImportDirectoryTable[$i]["NameRVA"] = $IDTArray[12..15]
                [Array]::Reverse($ImportDirectoryTable[$i]["NameRVA"])

                # # REMOVE CORRECT
                # Write-Host "DLL NAME RVA $([CustomConvert]::ToHexString($ImportDirectoryTable[$i]["NameRVA"]))"

                # Read DLL ILT RVA CORRECT
                $ImportDirectoryTable[$i]["ILTRVA"] = $IDTArray[0..3]
                [Array]::Reverse($ImportDirectoryTable[$i]["ILTRVA"])

                # # REMOVE
                # Write-Host "ILT RVA $([CustomConvert]::ToHexString($ImportDirectoryTable[$i]["ILTRVA"]))"

                # Use ILT RVA to get location of import name ISSUE
                $ImportLookupTableOffset = [Math]::ABS([System.Convert]::ToInt64([CustomConvert]::ToHexString($ImportDirectoryTable[$i]["ILTRVA"]), 16) - [System.Convert]::ToInt64($SectionsTableStrings[$IDTSection]["VirtualAddress"], 16))
                $ImportLookupTableSeek = $ImportLookupTableOffset + [System.Convert]::ToInt64($SectionsTableStrings[$IDTSection]["PointerToRawData"], 16)

                # # REMOVE ISSUE
                # Write-Host "ILTOFFSET $($ImportLookupTableOffset)"
                # Write-Host "ILTSEEK $($ImportLookupTableSeek)"

                # Use Name RVA to get location of Name 
                $ImportDirectoryOffset = [Math]::ABS([System.Convert]::ToInt64([CustomConvert]::ToHexString($ImportDirectoryTable[$i]["NameRVA"]), 16) - [System.Convert]::ToInt64($SectionsTableStrings[$IDTSection]["VirtualAddress"], 16))
                $ImportNameSeek = $ImportDirectoryOffset + [System.Convert]::ToInt64($SectionsTableStrings[$IDTSection]["PointerToRawData"], 16)

                # Seek name
                $File.Seek($ImportNameSeek, 0) | Out-Null
                $ImportDLLArray = [System.Byte[]]::CreateInstance([System.Byte], 20)  
                $File.Read($ImportDLLArray, 0, 20) | Out-Null

                # # REMOVE
                # Write-Host "ImportDLLARRAY $([CustomConvert]::ToHexString($ImportDLLArray))"

                # Seek ILT name ISSUE
                $File.Seek($ImportLookupTableSeek, 0) | Out-Null
                $ImportLookupArray = [System.Byte[]]::CreateInstance([System.Byte], 25) 
                $File.Read($ImportLookupArray, 0, 25) | Out-Null


                # # REMOVE ISSUE
                # Write-Host "IMPORTLOOKUPARRAY $([CustomConvert]::ToHexString($ImportLookupArray))"

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
                $ImportDLLNameArray += $ImportDLLName
                # DLL
                # write-host "DLLName:" $ImportDLLName
                # ILT _CorExeMain for executables and _CorDllMain for DLLs
                # Write-Host "DLL Import:" $ImportLookupName
                $IDTSeek += 20 
            }

        # If there's no CLRRuntime Header, skip all processing and finish analysis
        if([System.Convert]::ToInt64([CustomConvert]::ToHexString($CLRRuntimeHeader),16) -ne 0){
            # Parse CLR Runtime Header to get EntryPoint of metadata streams
            # Use CLRRuntime RVA and size to get NETHeader
            # https://www.codeproject.com/Articles/12585/The-NET-File-Format
            $NETheaderRVA = $CLRRuntimeHeader[4..7]
            $NETHeaderOffset = [Math]::ABS([System.Convert]::ToInt64([CustomConvert]::ToHexString($NETheaderRVA), 16) - [System.Convert]::ToInt64($SectionsTableStrings[0]["VirtualAddress"], 16))
            $NETHeaderSeek = $NETHeaderOffset + [System.Convert]::ToInt64($SectionsTableStrings[0]["PointerToRawData"], 16)
            $File.Seek($NETHeaderSeek, 0) | Out-Null
            $NETHeaderArray = [System.Byte[]]::CreateInstance([System.Byte], [System.Convert]::ToInt64([CustomConvert]::ToHexString($CLRRuntimeHeader[0..3]), 16))
            $File.Read($NETHeaderArray, 0, [System.Convert]::ToInt64([CustomConvert]::ToHexString($CLRRuntimeHeader[0..3]), 16)) | Out-Null
            
                # # REMOVE
                # WRITE-HOST "CLRRUNTIMEHEADER $($CLRRuntimeHeader)"
                # Write-Host "NETHEADER $([CustomConvert]::ToHexString($NETHeaderArray))"

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
            $MetaDataOffset = [System.Convert]::ToInt64([CustomConvert]::ToHexString($NETMetaDataRVA), 16) - [System.Convert]::ToInt64($SectionsTableStrings[0]["VirtualAddress"], 16)
            $MetaDataSeek = $MetaDataOffset + [System.Convert]::ToInt64($SectionsTableStrings[0]["PointerToRawData"], 16)
            $File.Seek($MetaDataSeek, 0) | Out-Null
            $MetaDataArray = [System.Byte[]]::CreateInstance([System.Byte], [System.Convert]::ToInt64([CustomConvert]::ToHexString($NETMetaDataSize[0..3]), 16))
            $File.Read($MetaDataArray, 0, [System.Convert]::ToInt64([CustomConvert]::ToHexString($NETMetaDataSize[0..3]), 16)) | Out-Null

            # Get the StreamHeader from the MetaData Header
            # Need to find the length of the version string first to ensure that the proper offset is read
            $MetaDataHeaderStringSize = $MetaDataArray[12..15]
            [array]::Reverse($MetaDataHeaderStringSize)
            $MetaDataHeaderStringSize = [System.Convert]::ToInt64([CustomConvert]::ToHexString($MetaDataHeaderStringSize), 16)

            # Get number of streams
            $MetaDataStreams = $MetaDataArray[($MetaDataHeaderStringSize + 18)..($MetaDataHeaderStringSize + 19)]
            [Array]::Reverse($MetaDataStreams)
            $MetaDataStreams = [System.Convert]::ToInt64([CustomConvert]::ToHexString($MetaDataStreams), 16)

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
                    $MetaDataTableOffset = [System.Convert]::ToInt64([CustomConvert]::ToHexString($MetaDataStream[$i]["Offset"]), 16) + $MetaDataSeek
                }
                if($MetaDataStream[$i]["Name"] -eq "#Strings"){

                    # Get the offset of the strings table
                    $StringsDataTableOffset = [System.Convert]::ToInt64([CustomConvert]::ToHexString($MetaDataStream[$i]["Offset"]), 16) + $MetaDataSeek
                    $StringsHeapSize = [System.Convert]::ToInt64([CustomConvert]::ToHexString($MetaDataStream[$i]["Size"]), 16)
                }
            }

            # Get String Heap 
            # Read entire heap and apply offset as numeric starting point as in Stream parsing
            $StringHeap = [System.Byte[]]::CreateInstance([System.Byte], $StringsHeapSize)
            $File.Seek($StringsDataTableOffset, 0) | Out-Null
            $File.Read($StringHeap, 0, $StringsHeapSize) | Out-Null


            # Parse the #~ MetaData Table 
            $MetaDataTable = [System.Byte[]]::CreateInstance([System.Byte], 24)
            $File.Seek($MetaDataTableOffset, 0) | Out-Null
            $File.Read($MetaDataTable, 0, 24) | Out-Null


            # Calculate tables present from Valid bitmask
            # Convert to binary and count 1s
            $ValidBitmask = $MetaDataTable[8..15]
            [Array]::Reverse($ValidBitmask)
            $BinaryTables = [System.Convert]::ToString([System.Convert]::ToInt64([CustomConvert]::ToHexString($ValidBitmask), 16), 2)

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
                $File.Read($TableSizeArray[$i]["Size"], 0, 4)  | Out-Null
                [Array]::Reverse($TableSizeArray[$i]["Size"])
                $TableSizeArray[$i]["Size"] = [System.Convert]::ToInt64([CustomConvert]::ToHexString($TableSizeArray[$i]["Size"]), 16)
            }

            # If $i = needed table, read the table. Else, skip $i["Size"] bytes
            # offset by 1 because of array style
            # Define arrays within the cases
            # Each table needs to be defined to skip as they are variable lengths
            foreach($i in $occupiedSlots){
                switch($i){

                    # Module
                    1 {$File.Seek(($TableSizeArray[$i]["Size"] * 10), 1) | Out-Null}

                    # TypeRef
                    2 {
                        $TypeRefMembers = @{}
                        $TypeRefNames = @()
                        $TypeRefNamespace = @()
                        for($j=0;$j -lt $TableSizeArray[2]["Size"];$j++){
                            $TypeRef = [System.Byte[]]::CreateInstance([System.Byte], 6)
                            $TypeRefMembers[$j] = @{}
                            $File.Read($TypeRef, 0, 6) | Out-Null

                            # Set offset to name
                            $TypeRefMembers[$j]["Name"] = $TypeRef[2..3]
                            [Array]::Reverse($TypeRefMembers[$j]["Name"])

                            # Set offset to namespace
                            $TypeRefMembers[$j]["Namespace"] = $TypeRef[4..5]
                            [Array]::Reverse($TypeRefMembers[$j]["Namespace"])
                            
                            # Get Name
                            $ObjName = $null
                            foreach($x in $StringHeap[([System.Convert]::ToInt64([CustomConvert]::ToHexString($TypeRefMembers[$j]["Name"]), 16))..([System.Convert]::ToInt64([CustomConvert]::ToHexString($TypeRefMembers[$j]["Name"]), 16) + 30)]){
                                if($x -ne 0){
                                    $ObjName += [char]$x
                                }else{
                                    break
                                }
                            }
                            $TypeRefNames += $ObjName

                            # Get Namespace
                            $ObjNamespace = $null
                            foreach($x in $StringHeap[([System.Convert]::ToInt64([CustomConvert]::ToHexString($TypeRefMembers[$j]["Namespace"]), 16))..([System.Convert]::ToInt64([CustomConvert]::ToHexString($TypeRefMembers[$j]["Namespace"]), 16) + 30)]){
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

                    3 {$File.Seek(($TableSizeArray[$i]["Size"] * 14), 1) | Out-Null}
                    # 4 {$File.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}
                    5 {$File.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}
                    # 6 {$File.Seek(($TableSizeArray[$i]["Size"] * 10), 1) | Out-Null}
                    
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
                            $File.Read($Method, 0, 14) | Out-Null

                            # Set offset to name
                            $MethodMembers[$j]["Name"] = $Method[8..9]

                            # Reverse endian
                            [Array]::Reverse($MethodMembers[$j]["Name"])
                            
                            # Create a null object to store the char name array
                            $ObjName = $null

                            # Get the location of the string name in the heap and read 30 bytes worth of the array, storing valid char bytes into $objName
                            foreach($x in $StringHeap[([System.Convert]::ToInt64([CustomConvert]::ToHexString($MethodMembers[$j]["Name"]), 16))..([System.Convert]::ToInt64([CustomConvert]::ToHexString($MethodMembers[$j]["Name"]), 16) + 30)]){
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

                    # 8 {$File.Seek(($TableSizeArray[$i]["Size"] * 10), 1) | Out-Null}

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
                            $File.Read($Param, 0, 6) | Out-Null

                            # Set offset to name
                            $ParamMembers[$j]["Name"] = $Param[4..5]

                            # Reverse endian
                            [Array]::Reverse($ParamMembers[$j]["Name"])
                            
                            # Create a null object to store the char name array
                            $ObjName = $null

                            # Get the location of the string name in the heap and read 30 bytes worth of the array, storing valid char bytes into $objName
                            foreach($x in $StringHeap[([System.Convert]::ToInt64([CustomConvert]::ToHexString($ParamMembers[$j]["Name"]), 16))..([System.Convert]::ToInt64([CustomConvert]::ToHexString($ParamMembers[$j]["Name"]), 16) + 30)]){
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

                    10 {$File.Seek(($TableSizeArray[$i]["Size"] * 4), 1) | Out-Null}

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
                            $File.Read($MemberRef, 0, 6) | Out-Null

                            # Set offset to name
                            $MemberRefMembers[$j]["Name"] = $MemberRef[2..3]

                            # Reverse endian
                            [Array]::Reverse($MemberRefMembers[$j]["Name"])
                            
                            # Create a null object to store the char name array
                            $ObjName = $null

                            # Get the location of the string name in the heap and read 30 bytes worth of the array, storing valid char bytes into $objName
                            foreach($x in $StringHeap[([System.Convert]::ToInt64([CustomConvert]::ToHexString($MemberRefMembers[$j]["Name"]), 16))..([System.Convert]::ToInt64([CustomConvert]::ToHexString($MemberRefMembers[$j]["Name"]), 16) + 30)]){
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

                    12 {$File.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}
                    13 {$File.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}
                    14 {$File.Seek(($TableSizeArray[$i]["Size"] * 4), 1) | Out-Null}
                    15 {$File.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}
                    16 {$File.Seek(($TableSizeArray[$i]["Size"] * 8), 1) | Out-Null}
                    17 {$File.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}
                    18 {$File.Seek(($TableSizeArray[$i]["Size"] * 2), 1) | Out-Null}
                    19 {$File.Seek(($TableSizeArray[$i]["Size"] * 4), 1) | Out-Null}
                    # 20 {$File.Seek(($TableSizeArray[$i]["Size"] * 10), 1) | Out-Null}

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
                            $File.Read($EventEntry, 0, 6) | Out-Null

                            # Set offset to name
                            $EventMembers[$j]["Name"] = $EventEntry[2..3]

                            # Reverse endian
                            [Array]::Reverse($EventMembers[$j]["Name"])
                            
                            # Create a null object to store the char name array
                            $ObjName = $null

                            # Get the location of the string name in the heap and read 30 bytes worth of the array, storing valid char bytes into $objName
                            foreach($x in $StringHeap[([System.Convert]::ToInt64([CustomConvert]::ToHexString($EventMembers[$j]["Name"]), 16))..([System.Convert]::ToInt64([CustomConvert]::ToHexString($EventMembers[$j]["Name"]), 16) + 30)]){
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

                    22 {$File.Seek(($TableSizeArray[$i]["Size"] * 4), 1) | Out-Null}
                    # 23 {$File.Seek(($TableSizeArray[$i]["Size"] * 10), 1) | Out-Null}
                    24 {$File.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}
                    25 {$File.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}
                    26 {$File.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}

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
                            $File.Read($ModuleRef, 0, 2) | Out-Null

                            # Set offset to name
                            $ModuleRefMembers[$j]["Name"] = $ModuleRef[0..1]

                            # Reverse endian
                            [Array]::Reverse($ModuleRefMembers[$j]["Name"])
                            
                            # Create a null object to store the char name array
                            $ObjName = $null

                            # Get the location of the string name in the heap and read 30 bytes worth of the array, storing valid char bytes into $objName
                            foreach($x in $StringHeap[([System.Convert]::ToInt64([CustomConvert]::ToHexString($ModuleRefMembers[$j]["Name"]), 16))..([System.Convert]::ToInt64([CustomConvert]::ToHexString($ModuleRefMembers[$j]["Name"]), 16) + 30)]){
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

                    28 {$File.Seek(($TableSizeArray[$i]["Size"] * 2), 1) | Out-Null}

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
                            $File.Read($ImplMap, 0, 8) | Out-Null

                            # Set offset to name
                            $ImplMapMembers[$j]["Name"] = $ImplMap[4..5]

                            # Reverse endian
                            [Array]::Reverse($ImplMapMembers[$j]["Name"])
                            
                            # Create a null object to store the char name array
                            $ObjName = $null

                            # Get the location of the string name in the heap and read 30 bytes worth of the array, storing valid char bytes into $objName
                            foreach($x in $StringHeap[([System.Convert]::ToInt64([CustomConvert]::ToHexString($ImplMapMembers[$j]["Name"]), 16))..([System.Convert]::ToInt64([CustomConvert]::ToHexString($ImplMapMembers[$j]["Name"]), 16) + 30)]){
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

                    30 {$File.Seek(($TableSizeArray[$i]["Size"] * 6), 1) | Out-Null}
                    # 31 {$File.Seek(($TableSizeArray[$i]["Size"] * 10), 1) | Out-Null}
                    # 32 {$File.Seek(($TableSizeArray[$i]["Size"] * 10), 1) | Out-Null}
                    33 {$File.Seek(($TableSizeArray[$i]["Size"] * 22), 1) | Out-Null}
                    34 {$File.Seek(($TableSizeArray[$i]["Size"] * 4), 1) | Out-Null}
                    35 {$File.Seek(($TableSizeArray[$i]["Size"] * 12), 1) | Out-Null}

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
                            $File.Read($AssemblyRef, 0, 20) | Out-Null

                            # Set offset to name
                            $AssemblyRefMembers[$j]["Name"] = $AssemblyRef[14..15]

                            # Reverse endian
                            [Array]::Reverse($AssemblyRefMembers[$j]["Name"])
                            
                            # Create a null object to store the char name array
                            $ObjName = $null

                            # Get the location of the string name in the heap and read 30 bytes worth of the array, storing valid char bytes into $objName
                            foreach($x in $StringHeap[([System.Convert]::ToInt64([CustomConvert]::ToHexString($AssemblyRefMembers[$j]["Name"]), 16))..([System.Convert]::ToInt64([CustomConvert]::ToHexString($AssemblyRefMembers[$j]["Name"]), 16) + 30)]){
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
        }


        # Close file
        $File.Dispose() 
        $File.Close()


        # Convert to strings for operations and printing
        $OptionalHeaders = [CustomConvert]::ToHexString($OptionalHeaders)
        $OptionalHeaders = $OptionalHeaders -replace '..(?!$)','$0 '
    
        # Get time stamp from COFF header
        [byte[]]$TimeStamp = $COFFHeader[4..7] 
        [Array]::Reverse($TimeStamp)
        [string]$Timestamp = (([System.DateTimeOffset]::FromUnixTimeSeconds([System.Convert]::ToInt64([CustomConvert]::ToHexString($TimeStamp),16))).DateTime).ToString("s")
    
        # Convert to strings for operations and printing
        $COFFHeader = [CustomConvert]::ToHexString($COFFHeader)
        $COFFHeader = $COFFHeader -replace '..(?!$)','$0 '
    
        $ImportTable = [CustomConvert]::ToHexString($ImportTable)
        $ImportTable = $ImportTable -replace '..(?!$)','$0 '
    
        # $SectionsTableStrings[$i]["PointerToRawData"] = $SectionsTableStrings[$i]["PointerToRawData"] -replace '..(?!$)','$0 '
    
        # Operate on strings and print results
        switch -Wildcard ($COFFHeader){
            "4C*" {$Bit = "32-Bit";break}
            "64*" {$Bit = "64-Bit";break}
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
            $MetaDataStream[$i]["Offset"] = [CustomConvert]::ToHexString($MetaDataStream[$i]["Offset"]) -replace '..(?!$)','$0 '
            $StreamNames += $MetaDataStream[$i]["Name"]
            $StreamOffsets += $MetaDataStream[$i]["Offset"]
            # Write-Host "Size:" $MetaDataStream[$i]["Size"]
        }
    
        # Object
        $Results = New-Object PSObject -Property $([ordered]@{
            FileName = $Path
            Hash = (Get-FileHash -Path $Path).Hash
            Type = "$Bit" + " $PEType"
            TimeStamp = $TimeStamp
            Checksum = $CheckSum
            Packed = if($Packed){$true}else{$false}
            Entropy = if(!$SkipEntropyCheck){$entropy}else{"Entropy check skipped"}
            SectionNames = $SectionsNames
            SectionOffsets = $SectionsOffsets
            MetadataOffset = if($MetaDataSeek){$MetaDataSeek.ToString("X8") -replace '..(?!$)','$0 '};
            Streams = $StreamNames
            StreamsOffset = $StreamOffsets
            ImportTable = $ImportDLLNameArray
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
    return $Results
    }catch{
        Write-Log ($_.ScriptStackTrace).ToString() 1
        Write-Log ($_.Exception).ToString() 1
        Write-Log ($_.FullyQualifiedErrorId).ToString() 1
        $file.Close()
        return
    }
}

Function RepCheck(){
    if(!$APIKey){
        try {
            $APIKey = [System.Environment]::GetFolderPath("MyDocuments")
            [PSCustomObject]$APIKey = Get-Content "$APIKey\Invoke-FileAnalysis\APIKeys.json" -Raw |ConvertFrom-Json
            $APIKey = $APIKey.VTAPI 
            Write-Log "VirusTotal API Key found. Getting results." 1
        }
        catch {
            Write-log "VirusTotal API Key not found and not supplied." 1
            $Results = [PSCustomObject][Ordered]@{
                File = "API Key must be supplied"
                Determination = "API Key must be supplied"
                Hash = "API Key must be supplied"
                Malicious = "API Key must be supplied"
                Suspicious = "API Key must be supplied"
                Harmless = "API Key must be supplied"
                Raw = "API Key must be supplied"
                Link = "API Key must be supplied"
            }
            return $Results
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
    $hash = (Get-FileHash -LiteralPath $Path).Hash
    $Request = Invoke-RestMethod -SessionVariable VirusTotal -Uri "https://www.virustotal.com/api/v3/files/$hash" -Method Get -Headers @{"x-apikey"=$APIKey} 
    # stupid 5.1 
    # if($Request.StatusCode -ne 200){
    #     Write-Log "No results on file hash: $hash" 1
    # }else{
        Write-Log "VirusTotal Results found for hash: $hash" 1
        # more stupid powershell 5.1 stuff
        Add-Type -AssemblyName System.Web.Extensions
        $serial = [Web.Script.Serialization.JavaScriptSerializer]::new()
        $json = $Serial.Deserialize($Request, [hashtable])
        $Content = $json
        if($Content.data.attributes.last_analysis_stats.malicious -ge 5){
            $Determination = "Malicious"
        }elseif($Content.data.attributes.last_analysis_stats.malicious -ge 1 -Or $Content.data.attributes.last_analysis_stats.suspicious -ge 1){
            $Determination = "Suspicious"
        }else{
            $Determination = "Harmless"
        }
        $Results = [PSCustomObject][Ordered]@{
            File = $Path
            Determination = $Determination
            Hash = $hash
            Malicious = $Content.data.attributes.last_analysis_stats.malicious
            Suspicious = $Content.data.attributes.last_analysis_stats.suspicious
            Harmless = $Content.data.attributes.last_analysis_stats.harmless
            Raw = $Content
            Link = ($Content.data.links.self).replace("/api/v3/files/", "/gui/file/")
        }
        return $Results
    # }
}

# Default to 
Function Output($Results, $Rep){
    switch ($Style) {
        # Text file output
        "Text" { 
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

         }
        # Word report output
        # Might do this later, but unlikely
        "Report" {  }
        # Visual output
        "Object" { 
            $Results
            $Rep
         }
        # Defaults to printing out objects
        Default {
            # Add the Presentation Framework Assembly
            Add-Type -AssemblyName PresentationFramework

            # Create the XML data
            # Case sensitive
            # String Formatting to add stuff in
            $xaml =@"
            <Window
                xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
                x:Name="Window"
                Title="PE Analysis" Height="450" Width="800">
                <Grid>
                    <Menu x:Name="menu">
                        <MenuItem Header="_File">
                            <MenuItem Header="_Open" x:Name="MenuItem_Click">
                                <MenuItem.ToolTip>
                                    <ToolTip> Open a file for analyis</ToolTip>
                                </MenuItem.ToolTip>
                            </MenuItem>
                            <MenuItem Header="_Open (SkipOptionalChecks)" x:Name="Skip">
                                <MenuItem.ToolTip>
                                    <ToolTip> Open a file for analysis (skip entropy checking)</ToolTip>
                                </MenuItem.ToolTip>
                            </MenuItem>
                            <MenuItem Header="_Open (SkipEntropyCheck)" x:Name="SkipEntropyCheck">
                                <MenuItem.ToolTip>
                                    <ToolTip> Open a file for analysis (skip entropy checking)</ToolTip>
                                </MenuItem.ToolTip>
                            </MenuItem>
                            <MenuItem Header="_Open (SkipVirusTotalCheck)" x:Name="SkipVirusTotalCheck">
                                <MenuItem.ToolTip>
                                    <ToolTip> Open a file for analysis (skip entropy checking)</ToolTip>
                                </MenuItem.ToolTip>
                            </MenuItem>
                        </MenuItem>
                        <MenuItem Header="_Help" x:Name="MenuItem_Click_1">
                            <MenuItem.ToolTip>
                                <ToolTip>Display Help</ToolTip>
                            </MenuItem.ToolTip>
                        </MenuItem>
                        <MenuItem Header="_Log" x:Name="MenuItem_Log">
                            <MenuItem.ToolTip>
                                <ToolTip>Display Log</ToolTip>
                            </MenuItem.ToolTip>
                        </MenuItem>
                    </Menu>
                    <TabControl x:Name="tabControl" Margin="10,20,10,10">
                        <TabItem Header="General Information">
                            <Grid Background="#FFE5E5E5">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="5*"/>
                                    <ColumnDefinition Width="21*"/>
                                </Grid.ColumnDefinitions>
                                <!--<Rectangle HorizontalAlignment="Left" Height="189" Stroke="Black" VerticalAlignment="Top" Width="760" Margin="10,10,0,0" Fill="WhiteSmoke" Grid.ColumnSpan="2"/>-->
                                <Grid Margin="24,21,19,10" Grid.ColumnSpan="4" Grid.RowSpan="5">
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                    </Grid.RowDefinitions>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="1*"/>
                                        <ColumnDefinition Width="2*"/>
                                    </Grid.ColumnDefinitions>
                                    <!--Border Definitions-->
                                    <Border Grid.Column="0" Grid.Row="0" BorderBrush="Black" BorderThickness="1,1,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="1" Grid.Row="0" BorderBrush="Black" BorderThickness="0,1,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="0" Grid.Row="1" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="1" Grid.Row="1" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="0" Grid.Row="2" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="1" Grid.Row="2" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="0" Grid.Row="3" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="1" Grid.Row="3" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="0" Grid.Row="4" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="1" Grid.Row="4" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="0" Grid.Row="5" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="1" Grid.Row="5" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="0" Grid.Row="6" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="1" Grid.Row="6" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="0" Grid.Row="7" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="1" Grid.Row="7" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="0" Grid.Row="8" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="1" Grid.Row="8" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                    <!--Contents-->
                                    <!--Headers-->
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="0" Text=" Name"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="1" Grid.Row="0" Text=" Value"></TextBox>
                                    <!--Table Contents-->
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="1" Text=" File Name"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="1" Grid.Row="1" Text=" {0}"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="2" Text=" File Type"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="1" Grid.Row="2" Text=" {1}"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="3" Text=" Timestamp"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="1" Grid.Row="3" Text=" {2}"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="4" Text=" Checksum"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="1" Grid.Row="4" Text=" {3}"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="5" Text=" Packed"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="1" Grid.Row="5" Text=" {4}"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="6" Text=" Entropy"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="1" Grid.Row="6" Text=" {5}"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="7" Text=" Determination"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="1" Grid.Row="7" Text=" {6}"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="8" Text=" Hash"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="1" Grid.Row="8" Text=" {7}"></TextBox>
                                </Grid>
                            </Grid>
                        </TabItem>
"@ -f $Path, $Results.Type, $Results.TimeStamp, $Results.Checksum, $Results.Packed, $Results.Entropy, $Rep.Determination, $Results.Hash

$xaml+=@"

                        <TabItem Header="Sections">
                            <Grid Background="#FFE5E5E5">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="5*"/>
                                    <ColumnDefinition Width="21*"/>
                                </Grid.ColumnDefinitions>
                                <!--<Rectangle HorizontalAlignment="Left" Height="189" Stroke="Black" VerticalAlignment="Top" Width="760" Margin="10,10,0,0" Fill="WhiteSmoke" Grid.ColumnSpan="2"/>-->
                                <Grid Margin="24,21,19,208" Grid.ColumnSpan="4" Grid.RowSpan="5">
                                <!-- These should be dynamic too, but w/e -->
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                    </Grid.RowDefinitions>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="1*"/>
                                        <ColumnDefinition Width="2*"/>
                                    </Grid.ColumnDefinitions>
                                    <!--Border Definitions-->
                                    <Border Grid.Column="0" Grid.Row="0" BorderBrush="Black" BorderThickness="1,1,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="1" Grid.Row="0" BorderBrush="Black" BorderThickness="0,1,1,1" Background="WhiteSmoke"></Border>
                                    <!--Contents-->
                                    <!--Headers-->
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="0" Text=" Name"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="1" Grid.Row="0" Text=" Offset"></TextBox>
                                    <!--Table Contents-->
                                    <!--Inject dynamic grids based on number of Sections-->
"@
# For every section add the section name and offset
# Borders, textblocks, rows
# Row [$i]
for($i=1;$i -lt (($Results.SectionNames).Count + 1);$i++){
    $xaml+=@"

                                    <Border Grid.Column="0" Grid.Row="{0}" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="1" Grid.Row="{0}" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="{0}" Text=" {1}"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="1" Grid.Row="{0}" Text=" {2}"></TextBox>
"@ -f ($i), [String]::New($([System.Text.Encoding]::UTF8.GetBytes($Results.SectionNames[$i - 1].ToCharArray())|%{if(! $_ -eq 0){$_}})), $Results.SectionOffsets[$i-1]
}
# [string]::new($Results.SectionNames[$i-1][0..($Results.SectionNames[$i-1].length)])
$xaml+=@"

                                </Grid>
                            </Grid>
                        </TabItem>
                        <TabItem Header="Streams">
                            <Grid Background="#FFE5E5E5">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="5*"/>
                                    <ColumnDefinition Width="21*"/>
                                </Grid.ColumnDefinitions>
                                <!--<Rectangle HorizontalAlignment="Left" Height="189" Stroke="Black" VerticalAlignment="Top" Width="760" Margin="10,10,0,0" Fill="WhiteSmoke" Grid.ColumnSpan="2"/>-->
                                <Grid Margin="24,21,19,208" Grid.ColumnSpan="4" Grid.RowSpan="5">
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                    </Grid.RowDefinitions>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="1*"/>
                                        <ColumnDefinition Width="2*"/>
                                    </Grid.ColumnDefinitions>
                                    <!--Border Definitions-->
                                    <Border Grid.Column="0" Grid.Row="0" BorderBrush="Black" BorderThickness="1,1,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="1" Grid.Row="0" BorderBrush="Black" BorderThickness="0,1,1,1" Background="WhiteSmoke"></Border>
                                    <!--Contents-->
                                    <!--Headers-->
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="0" Text=" Name"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="1" Grid.Row="0" Text=" Offset"></TextBox>
                                    <!--Table Contents-->
"@
# Add streams in
for($i=1;$i -lt (($Results.Streams).Count + 1);$i++){
    $xaml+=@"

                                    <Border Grid.Column="0" Grid.Row="{0}" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="1" Grid.Row="{0}" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="{0}" Text=" {1}"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="1" Grid.Row="{0}" Text=" {2}"></TextBox>
"@ -f ($i), [string]::new($Results.Streams[$i-1]), $Results.StreamsOffset[$i-1]
}

$xaml+=@"
                                </Grid>
                            </Grid>
                        </TabItem>
                        <TabItem Header="Imports">
                            <Grid Background="#FFE5E5E5">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="5*"/>
                                    <ColumnDefinition Width="21*"/>
                                </Grid.ColumnDefinitions>
                                <!--<Rectangle HorizontalAlignment="Left" Height="354" Stroke="Black" VerticalAlignment="Top" Width="760" Margin="10,10,0,0" Fill="WhiteSmoke" Grid.ColumnSpan="2"/>-->
                                <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" Grid.ColumnSpan="2" Margin="10,18,16,40" >
                                    <Grid Margin="24,21,19,17" Grid.ColumnSpan="2">
                                        <Grid.RowDefinitions>
                                            <RowDefinition Height="Auto"/>
                                            <RowDefinition Height="Auto"/>
                                        </Grid.RowDefinitions>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="1*"/>
                                            <ColumnDefinition Width="2*"/>
                                        </Grid.ColumnDefinitions>
                                        <!--Border Definitions-->
                                        <Border Grid.Column="0" Grid.Row="0" BorderBrush="Black" BorderThickness="1,1,1,1" Background="WhiteSmoke"></Border>
                                        <Border Grid.Column="1" Grid.Row="0" BorderBrush="Black" BorderThickness="0,1,1,1" Background="WhiteSmoke"></Border>
                                        <Border Grid.Column="0" Grid.Row="1" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                        <Border Grid.Column="1" Grid.Row="1" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke" x:Name="ImportListHeight"></Border>
                                        <!--Contents-->
                                        <!--Headers-->
                                        <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="0" Text=" ImportTable"></TextBox>
                                        <ListBox x:Name="ImportTableListBox" Grid.Column="1" Grid.Row="0" ScrollViewer.VerticalScrollBarVisibility="Auto" HorizontalAlignment="Stretch" VerticalAlignment="Stretch">
"@
# Add in listbox import table elements
for($i=0;$i -lt ($Results.ImportTable).Count; $i++){
    $xaml+=@"
                                            <ListBoxItem>{0}</ListBoxItem>
"@ -f $Results.ImportTable[$i]
}
$xaml+=@"

                                        </ListBox>
                                        <!--Table Contents-->
                                        <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="1" Text=" Imports"></TextBox>
                                        <ListBox x:Name="ImportsListBox" Grid.Column="1" Grid.Row="1" ScrollViewer.VerticalScrollBarVisibility="Auto">
"@
# Add in listbox import elements
for($i=0;$i -lt ($Results.Imports).Count; $i++){
    $xaml+=@"
                                            <ListBoxItem>{0}</ListBoxItem>
"@ -f $Results.Imports[$i]
}


$xaml+=@"

                                        </ListBox>
                                    </Grid>
                                </ScrollViewer>
                            </Grid>
                        </TabItem>
                        <TabItem Header="MetaData Tables">
                            <Grid Background="#FFE5E5E5">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="5*"/>
                                    <ColumnDefinition Width="21*"/>
                                </Grid.ColumnDefinitions>
                                <!--<Rectangle HorizontalAlignment="Left" Height="354" Stroke="Black" VerticalAlignment="Top" Width="760" Margin="10,10,0,0" Fill="WhiteSmoke" Grid.ColumnSpan="2"/>-->
                                <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" Grid.ColumnSpan="2" Margin="10,18,16,40" >
                                    <Grid Margin="24,21,19,17" Grid.ColumnSpan="2">
                                        <Grid.RowDefinitions>
                                            <RowDefinition Height="Auto"/>
                                            <RowDefinition Height="Auto"/>
                                            <RowDefinition Height="Auto"/>
                                            <RowDefinition Height="Auto"/>
                                            <RowDefinition Height="Auto"/>
                                            <RowDefinition Height="Auto"/>
                                            <RowDefinition Height="Auto"/>
                                            <RowDefinition Height="Auto"/>
                                        </Grid.RowDefinitions>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="1*"/>
                                            <ColumnDefinition Width="2*"/>
                                        </Grid.ColumnDefinitions>
                                        <!--Border Definitions-->
                                        <Border Grid.Column="0" Grid.Row="0" BorderBrush="Black" BorderThickness="1,1,1,1" Background="WhiteSmoke"></Border>
                                        <Border Grid.Column="1" Grid.Row="0" BorderBrush="Black" BorderThickness="0,1,1,1" Background="WhiteSmoke"></Border>
                                        <Border Grid.Column="0" Grid.Row="1" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                        <Border Grid.Column="1" Grid.Row="1" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                        <Border Grid.Column="0" Grid.Row="2" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                        <Border Grid.Column="1" Grid.Row="2" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                        <Border Grid.Column="0" Grid.Row="3" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                        <Border Grid.Column="1" Grid.Row="3" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                        <Border Grid.Column="0" Grid.Row="4" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                        <Border Grid.Column="1" Grid.Row="4" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                        <Border Grid.Column="0" Grid.Row="5" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                        <Border Grid.Column="1" Grid.Row="5" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                        <Border Grid.Column="0" Grid.Row="6" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                        <Border Grid.Column="1" Grid.Row="6" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                        <Border Grid.Column="0" Grid.Row="7" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                        <Border Grid.Column="1" Grid.Row="7" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                        <!--Contents-->
                                        <!--Headers-->
                                        <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="0" Text=" TypeRefNames"></TextBox>
                                        <ListBox x:Name="MetaDataTypeReflistBox" Grid.Column="1" Grid.Row="0" ScrollViewer.VerticalScrollBarVisibility="Auto" MaxHeight="350">
"@
# Add in listbox TypeRef elements
for($i=0;$i -lt ($Results.TypeRefNames).Count; $i++){
    $xaml+=@"
                                        <ListBoxItem>{0}</ListBoxItem>
"@ -f $Results.TypeRefNames[$i]
}

$xaml+=@"

                                        </ListBox>
                                        <!--Table Contents-->
                                        <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="1" Text=" TypeRefNamespace"></TextBox>
                                        <ListBox x:Name="MetaDataTypeRefNamespacelistBox" Grid.Column="1" Grid.Row="1" ScrollViewer.VerticalScrollBarVisibility="Auto" MaxHeight="350">
"@
# Add in listbox TypeRefNamespace elements
for($i=0;$i -lt ($Results.TypeRefNamespace).Count; $i++){
    $xaml+=@"
                                        <ListBoxItem>{0}</ListBoxItem>
"@ -f $Results.TypeRefNamespace[$i]
}

$xaml+=@"

                                        </ListBox>
                                        <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="2" Text=" Methods"></TextBox>
                                        <ListBox x:Name="MetaDataMethodslistBox" Grid.Column="1" Grid.Row="2" ScrollViewer.VerticalScrollBarVisibility="Auto" MaxHeight="350">
"@
# Add in listbox Methods elements
for($i=0;$i -lt ($Results.Methods).Count; $i++){
    $xaml+=@"
                                        <ListBoxItem>{0}</ListBoxItem>
"@ -f $Results.Methods[$i]
}

$xaml+=@"

                                        </ListBox>
                                        <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="3" Text=" Params"></TextBox>
                                        <ListBox x:Name="MetaDataParamslistBox" Grid.Column="1" Grid.Row="3" ScrollViewer.VerticalScrollBarVisibility="Auto" MaxHeight="350">
"@
# Add in listbox Params elements
for($i=0;$i -lt ($Results.Params).Count; $i++){
    $xaml+=@"
                                        <ListBoxItem>{0}</ListBoxItem>
"@ -f $Results.Params[$i]
}

$xaml+=@"

                                        </ListBox>
                                        <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="4" Text=" MemberRef"></TextBox>
                                        <ListBox x:Name="MetaDataMemberEeflistBox" Grid.Column="1" Grid.Row="4" ScrollViewer.VerticalScrollBarVisibility="Auto" MaxHeight="350">
"@
# Add in listbox MemberRef elements
for($i=0;$i -lt ($Results.MemberRef).Count; $i++){
    $xaml+=@"
                                        <ListBoxItem>{0}</ListBoxItem>
"@ -f $Results.MemberRef[$i]
}

$xaml+=@"

                                        </ListBox>
                                        <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="5" Text=" Events"></TextBox>
                                        <ListBox x:Name="MetaDataEventslistBox" Grid.Column="1" Grid.Row="5" ScrollViewer.VerticalScrollBarVisibility="Auto" MaxHeight="350">
"@
# Add in listbox Events elements
for($i=0;$i -lt ($Results.Events).Count; $i++){
    $xaml+=@"
                                        <ListBoxItem>{0}</ListBoxItem>
"@ -f $Results.Events[$i]
}

$xaml+=@"

                                        </ListBox>
                                        <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="6" Text=" ModuleRef"></TextBox>
                                        <ListBox x:Name="MetaDataModuleReflistBox" Grid.Column="1" Grid.Row="6" ScrollViewer.VerticalScrollBarVisibility="Auto" MaxHeight="350">
"@
# Add in listbox ModuleRef elements
for($i=0;$i -lt ($Results.ModuleRef).Count; $i++){
    $xaml+=@"
                                        <ListBoxItem>{0}</ListBoxItem>
"@ -f $Results.ModuleRef[$i]
}

$xaml+=@"
                                        </ListBox>
                                        <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="7" Text=" AssemblyRef"></TextBox>
                                        <ListBox x:Name="MetaDataAssemblyReflistBox" Grid.Column="1" Grid.Row="7" ScrollViewer.VerticalScrollBarVisibility="Auto" MaxHeight="350">
"@
# Add in listbox AssemblyRef elements
for($i=0;$i -lt ($Results.AssemblyRef).Count; $i++){
    $xaml+=@"
                                        <ListBoxItem>{0}</ListBoxItem>
"@ -f $Results.AssemblyRef[$i]
}
$xaml+=@"

                                        </ListBox>
                                    </Grid>
                                </ScrollViewer>
                            </Grid>
                        </TabItem>
                        <TabItem Header="VirusTotal Results">
                            <Grid Background="#FFE5E5E5">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="5*"/>
                                    <ColumnDefinition Width="21*"/>
                                </Grid.ColumnDefinitions>
                                <!--<Rectangle HorizontalAlignment="Left" Height="189" Stroke="Black" VerticalAlignment="Top" Width="760" Margin="10,10,0,0" Fill="WhiteSmoke" Grid.ColumnSpan="2"/>-->
                                <Grid Margin="24,21,19,208" Grid.ColumnSpan="4" Grid.RowSpan="5">
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                    </Grid.RowDefinitions>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="1*"/>
                                        <ColumnDefinition Width="2*"/>
                                    </Grid.ColumnDefinitions>
                                    <!--Border Definitions-->
                                    <Border Grid.Column="0" Grid.Row="0" BorderBrush="Black" BorderThickness="1,1,1,1" Background="White"></Border>
                                    <Border Grid.Column="1" Grid.Row="0" BorderBrush="Black" BorderThickness="0,1,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="0" Grid.Row="1" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="1" Grid.Row="1" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="0" Grid.Row="2" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="1" Grid.Row="2" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="0" Grid.Row="3" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="1" Grid.Row="3" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="0" Grid.Row="4" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="1" Grid.Row="4" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="0" Grid.Row="5" BorderBrush="Black" BorderThickness="1,0,1,1" Background="WhiteSmoke"></Border>
                                    <Border Grid.Column="1" Grid.Row="5" BorderBrush="Black" BorderThickness="0,0,1,1" Background="WhiteSmoke"></Border>
                                    <!--Contents-->
                                    <!--Headers-->
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="0" Text=" File Hash"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="1" Grid.Row="0" Text=" {0}"></TextBox>
                                    <!--Table Contents-->
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="1" Text=" Determination"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="1" Grid.Row="1" Text=" {1}"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="2" Text=" Malicious"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="1" Grid.Row="2" Text=" {2}"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="3" Text=" Suspicious"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="1" Grid.Row="3" Text=" {3}"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="4" Text=" Harmless"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="1" Grid.Row="4" Text=" {4}"></TextBox>
                                    <TextBox Background="Transparent" BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap" Grid.Column="0" Grid.Row="5" Text=" Link" ></TextBox>
                                    <TextBlock Grid.Column="1" Grid.Row="5">
                                        <Hyperlink x:Name="VTLink">
                                            <TextBlock x:Name="VTLinkText"> 
                                                {5} 
                                            </TextBlock>
                                        </Hyperlink>
                                    </TextBlock>
                                </Grid>
                            </Grid>
                        </TabItem>
                    </TabControl>

                </Grid>
            </Window>
"@ -f $Results.Hash, $rep.Determination, $Rep.Malicious, $Rep.Suspicious, $Rep.Harmless, $Rep.Link
            # Create the reader
            $reader = (New-Object System.Xml.XmlNodeReader $([XML]$xaml))

            # Load reader
            $window = [Windows.Markup.XamlReader]::Load($reader)

            # Code happens here

            # Find the element by name
            $fileClick = $Window.FindName("MenuItem_Click")
            $HelpClick = $window.FindName("MenuItem_Click_1")
            $FileClickSkip = $Window.FindName("Skip")
            $FileClickSkipVT = $Window.FindName("SkipVirusTotalCheck")
            $FileClickSkipET = $Window.FindName("SkipEntropyCheck")
            $FileClickLog = $Window.FindName("MenuItem_Log")
            $ImportListClick = $window.FindName("ImportTableListBox")
            $ImportListBoxClick = $Window.FindName("ImportsListBox")
            $MetaDataTypeReflistBox = $Window.FindName("MetaDataTypeReflistBox")
            $MetaDataTypeRefNamespacelistBox = $Window.FindName("MetaDataTypeRefNamespacelistBox")
            $MetaDataMethodslistBox = $Window.FindName("MetaDataMethodslistBox")
            $MetaDataParamslistBox = $Window.FindName("MetaDataParamslistBox")
            $MetaDataMemberEeflistBox = $Window.FindName("MetaDataMemberEeflistBox")
            $MetaDataEventslistBox = $Window.FindName("MetaDataEventslistBox")
            $MetaDataModuleReflistBox = $Window.FindName("MetaDataModuleReflistBox")
            $MetaDataAssemblyReflistBox = $Window.FindName("MetaDataAssemblyReflistBox")
            $VTLink = $Window.FindName("VTLink")
            $VTLinkText = $Window.FindName("VTLinkText")

            $ImportListClick.Add_MouseDoubleClick({
                start "https://www.google.com/search?q=$(($ImportListClick.SelectedItem.ToString()).Split(" ")[1])"
            })
            $ImportListBoxClick.Add_MouseDoubleClick({
                start "https://www.google.com/search?q=$(($ImportListBoxClick.SelectedItem.ToString()).Split(" ")[1])"
            })
            $MetaDataTypeReflistBox.Add_MouseDoubleClick({
                start "https://www.google.com/search?q=$(($MetaDataTypeReflistBox.SelectedItem.ToString()).Split(" ")[1])"
            })
            $MetaDataTypeRefNamespacelistBox.Add_MouseDoubleClick({
                start "https://www.google.com/search?q=$(($MetaDataTypeRefNamespacelistBox.SelectedItem.ToString()).Split(" ")[1])"
            })
            $MetaDataMethodslistBox.Add_MouseDoubleClick({
                start "https://www.google.com/search?q=$(($MetaDataMethodslistBox.SelectedItem.ToString()).Split(" ")[1])"
            })
            $MetaDataParamslistBox.Add_MouseDoubleClick({
                start "https://www.google.com/search?q=$(($MetaDataParamslistBox.SelectedItem.ToString()).Split(" ")[1])"
            })
            $MetaDataMemberEeflistBox.Add_MouseDoubleClick({
                start "https://www.google.com/search?q=$(($MetaDataMemberEeflistBox.SelectedItem.ToString()).Split(" ")[1])"
            })
            $MetaDataEventslistBox.Add_MouseDoubleClick({
                start "https://www.google.com/search?q=$(($MetaDataEventslistBox.SelectedItem.ToString()).Split(" ")[1])"
            })
            $MetaDataModuleReflistBox.Add_MouseDoubleClick({
                start "https://www.google.com/search?q=$(($MetaDataModuleReflistBox.SelectedItem.ToString()).Split(" ")[1])"
            })
            $MetaDataAssemblyReflistBox.Add_MouseDoubleClick({
                start "https://www.google.com/search?q=$(($MetaDataAssemblyReflistBox.SelectedItem.ToString()).Split(" ")[1])"
            })
            $VTLink.Add_Click({
                start $VTLinkText.Text
            })

            # Do something with the element
            [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")
            $fileClick.Add_Click({
                $OpenFile = New-Object System.Windows.Forms.OpenFileDialog
                $OpenFile.ShowDialog()
                if($OpenFile){
                    $window.Close()
                    Invoke-PEAnalysis -Path $OpenFile.FileName
                }
            })
            $FileClickSkip.Add_Click({
                $OpenFile = New-Object System.Windows.Forms.OpenFileDialog
                $OpenFile.ShowDialog()
                if($OpenFile){
                    if(($null -eq $rep) -And ($null -eq $Results)){
                        $window.Close()
                    } 
                    Invoke-PEAnalysis -Path $OpenFile.FileName -SkipEntropyCheck -SkipVirusTotalCheck
                    # Probably a better way to do this
                    # $window.Close()
                }
            })
            $FileClickSkipVT.Add_Click({
                $OpenFile = New-Object System.Windows.Forms.OpenFileDialog
                $OpenFile.ShowDialog()
                if($OpenFile){
                    if(($null -eq $rep) -And ($null -eq $Results)){
                        $window.Close()
                    } 
                    Invoke-PEAnalysis -Path $OpenFile.FileName -SkipVirusTotalCheck
                    # Probably a better way to do this
                    # $window.Close()
                }
            })
            $FileClickSkipET.Add_Click({
                $OpenFile = New-Object System.Windows.Forms.OpenFileDialog
                $OpenFile.ShowDialog()
                if($OpenFile){
                    if(($null -eq $rep) -And ($null -eq $Results)){
                        $window.Close()
                    } 
                    Invoke-PEAnalysis -Path $OpenFile.FileName -SkipEntropyCheck
                    # Probably a better way to do this
                    # $window.Close()
                }
            })
            $FileClickLog.Add_Click({
                Start $LogFile
            })
            $HelpClick.Add_Click({
                [xml]$HelpMenu = @"
            <Window
                xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
                x:Name="Window"
                Title="PE Analysis Help" Height="450" Width="800">

                <Grid>
                    <Rectangle HorizontalAlignment="Left" Height="380" Stroke="Black" VerticalAlignment="Top" Width="760" Margin="10,10,10,10" Fill="WhiteSmoke" Grid.ColumnSpan="2"/>
                    <Grid Margin="24,21,19,208" Grid.ColumnSpan="2" Grid.RowSpan="2">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="1*"/>
                        </Grid.ColumnDefinitions>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>
                        <TextBlock Grid.Column="0" Grid.Row="0" Width="Auto">
                            <Bold>Help Menu</Bold>
                            <LineBreak />
                            <LineBreak />
                            <LineBreak />
                            <LineBreak />
                            This application performs PE file anaylsis of both PE32 and PE32+ files.
                            To get started, select an option under the files menu item.
                            <LineBreak />
                            SkipOptionalChecks will launch analysis without VirusTotal or Entropy checks.
                            <LineBreak />
                            You can see logged details by clicking on the log button.
                            <LineBreak />
                            Double clicking an item in a list will open a Google search for the item.
                            <LineBreak />
                            <LineBreak />
                            This is the very special PowerShell 5.1 version. Stuff might not work. Use the modern 7+ version for better support.
                            <LineBreak />
                            <LineBreak />
                            <LineBreak />
                            To learn more, visit https://www.github.com/lpowell
                        </TextBlock>
                    </Grid>
                </Grid>

                <!-- Client area containing the content of the window -->
            </Window>

"@

            $HelpReader = (New-Object System.Xml.XmlNodeReader $HelpMenu)
            $HelpWindow = [Windows.Markup.XamlReader]::Load($HelpReader)
            $HelpWindow.ShowDialog()

            })

            # Show window
            # Last item in script
            $window.ShowDialog()

            # https://4sysops.com/archives/create-a-gui-for-your-powershell-script-with-wpf/
                    }
    }
    return
}

# Launch Output 
Output $null $null