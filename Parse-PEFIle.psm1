function Parse-PEFile {
    param (
        [string]$filePath
    )

    # Load the assembly that provides access to PE headers
    Add-Type -AssemblyName 'System.Reflection.Metadata'

    # Read the PE file into a byte array
    $bytes = [System.IO.File]::ReadAllBytes($filePath)

    # Define offsets based on PE file structure for 64-bit files
    $peHeaderOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    $optionalHeaderOffset = $peHeaderOffset + 0x18
    $sectionHeadersOffset = $optionalHeaderOffset + 0x70  # This offset differs for 64-bit files
    $importDirectoryOffset = $optionalHeaderOffset + 0xA8  # This offset also differs for 64-bit files

    # Read the import directory RVA (Relative Virtual Address)
    $importDirectoryRVA = [BitConverter]::ToInt32($bytes, $importDirectoryOffset)

    # If the import directory RVA is zero, there are no imports
    if ($importDirectoryRVA -eq 0) {
        Write-Host "No imports found."
        return
    }

    # Read the import directory details
    $importDirectory = [BitConverter]::ToInt32($bytes, $sectionHeadersOffset + ($importDirectoryRVA - 0x400000))
    $importLookupTableRVA = [BitConverter]::ToInt32($bytes, $importDirectory + 0x0C)

    # Read the import lookup table RVA
    $importLookupTable = [BitConverter]::ToInt32($bytes, $sectionHeadersOffset + ($importLookupTableRVA - 0x400000))

    # Read import names and functions
    while ($true) {
        $importAddress = [BitConverter]::ToInt32($bytes, $importLookupTable)
        if ($importAddress -eq 0) {
            break
        }

        # Read the imported function's name
        $importNameRVA = [BitConverter]::ToInt32($bytes, $importAddress + 2)
        $importName = [System.Text.Encoding]::ASCII.GetString($bytes, $sectionHeadersOffset + ($importNameRVA - 0x400000), 50)
        $importName = $importName -split "`0" | Select-Object -First 1

        # Output the imported function
        Write-Host "Imported: $importName"

        # Move to the next entry in the import lookup table
        $importLookupTable += 4
    }

    # Read the export directory RVA
    $exportDirectoryRVA = [BitConverter]::ToInt32($bytes, $exportDirectoryOffset)

    # If the export directory RVA is zero, there are no exports
    if ($exportDirectoryRVA -eq 0) {
        Write-Host "No exports found."
        return
    }

    # Read the export directory details
    $exportDirectory = [BitConverter]::ToInt32($bytes, $sectionHeadersOffset + ($exportDirectoryRVA - 0x400000))
    $exportAddressTableRVA = [BitConverter]::ToInt32($bytes, $exportDirectory + 0x1C)
    $exportNamePointerRVA = [BitConverter]::ToInt32($bytes, $exportDirectory + 0x20)

    # Read export names and functions
    for ($i = 0; $i -lt [BitConverter]::ToInt32($bytes, $exportDirectory + 0x14); $i++) {
        $exportNameRVA = [BitConverter]::ToInt32($bytes, $sectionHeadersOffset + ($exportNamePointerRVA - 0x400000) + ($i * 4))
        $exportName = [System.Text.Encoding]::ASCII.GetString($bytes, $sectionHeadersOffset + ($exportNameRVA - 0x400000), 50)
        $exportName = $exportName -split "`0" | Select-Object -First 1

        # Output the exported function
        Write-Host "Exported: $exportName"
    }
}

# Use the function to parse a PE file (replace 'path_to_your_file.exe' with the actual path)
Parse-PEFile -filePath 'C:\Users\Liam Powell\OneDrive\Documents\Malware\WARNING-MALWARE-AHEAD\f1fcd\Artifacts\FireBaseEx[AgentTesla]'
