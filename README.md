# Invoke-FileAnalysis
PowerShell module for various file analysis tools.

Description:
This module contains various tools for file analysis. It will be updated per my own needs and recommendations/fixes. The goal is to provide similar functionality to other toolsets but built entirely in PowerShell for ease of use. It is not designed to replace traditional toolsets, only to provide alternative native PowerShell versions. 

Each module can accept values from piped commands 

    Get-ChildItem | %{Get-FileType $_} "
Modules also accept multiple files 

    Get-Strings "file1","file2","file3"



 Contains:
 Get-Strings 
 * Strings are defined as 4 or more printable ASCII characters ending in a new line or null byte.
 * This will be updated to support Unicode at some point.

Get-FileType
* Uses the first 10 bytes of any file or list of files to determine file type. Some signatures rely on extensions as well (if they exist). In undetermined files, the signature will be displayed for manual analysis.
* The included list was semi-generated with ChatGPT, more file signatures will be added eventually.

Get-VirusTotalAnalysis
* Submits the SHA256 hashes of the given file or list of files to VirusTotal and returns the detection stats and a URL to the page.
* Must submit an API key on first use. It will be saved to MyDocuments\Invoke-FileAnalysis\APIKeys.json after first use. 

Invoke-FileAnalysis
* Returns results of all modules (Strings is an optional switch)
* Will be updated to generate Word reports at some point. Currently, use *> or Out-String to redirect the output to a file. 
