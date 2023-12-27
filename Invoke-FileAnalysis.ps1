<#
Reverse engineering and file analysis tools

Name: Invoke-FileAnalysis (?)

Modules:
Get-FileType
Get-Strings




#>


function Get-FileType([Parameter(Position = 0)] [string[]] $Files){
   write-host $Files
}

Export-ModuleMember -Function Get-FileType