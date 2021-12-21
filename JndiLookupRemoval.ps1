<#
  .SYNOPSIS
  PowerShell script to Remove JndiLookup.class from Jar-files to remediate LOG4J Vulnerability until application vendors release patches for their products.
  
  This uses the inbuild compression library of .NET therefore no need to install any other zip-utility. This script works on all Windows Servers that have .Net 4.5 or higher installed:
  https://docs.microsoft.com/en-us/dotnet/api/system.io.compression.ziparchiveentry.delete?view=netframework-4.5

  https://logging.apache.org/log4j/2.x/security.html
    zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class

  Disclaimer see: https://github.com/nagten/JndiLookupRemoval

  .DESCRIPTION
  PowerShell script to Remove JndiLookup.class from Jar-files to remediate LOG4J Vulnerability.

  .EXAMPLE
  C:\PS> .\JndiLookupRemoval.ps1
  
  .LINK
  https://github.com/nagten/JndiLookupRemoval
  
  .NOTES
  Author: Nico Agten
  Last Edit: 17-Dec-2021
  Version 1.0 - Public initial release
#>

#Exclude versions that are not vulnerable
$ExcludedFiles = "log4j-core-2.12.2.jar", "log4j-core-2.16.0.jar", "log4j-core-2.17.0.jar"
$SearchString = "JndiLookup.class"

#Load IO.Compression library
[Reflection.Assembly]::LoadWithPartialName('System.IO.Compression')

#Get all Fixed drives
$Drives = [System.IO.DriveInfo]::getdrives() | Where-Object {$_.DriveType -eq 'Fixed'}

foreach($Drive in $Drives) {
    #Scan all *.jar files
    $VulnerableJarFiles = Get-ChildItem -Path $Drive.RootDirectory -Recurse -Force -Include *.jar -File -ErrorAction SilentlyContinue -Exclude $ExcludedFiles | ForEach-Object {Select-String $SearchString $_} | Select-Object -ExpandProperty Path
    
    #Only scan fils that use LOG4J naming convention
    #$VulnerableJarFiles = Get-ChildItem -Path $Drive.RootDirectory -Recurse -Force -Include log4j-core-*.jar -File -ErrorAction SilentlyContinue -Exclude $ExcludedFiles | ForEach-Object {Select-String $SearchString $_} | Select-Object -ExpandProperty Path
    
    #Remove doubles from list
    $VulnerableJarFiles = $VulnerableJarFiles | select -Unique

    foreach($VulnerableJarFile in $VulnerableJarFiles){
        Write-Host "Processing jar-file: $VulnerableJarFile"

        $FileStream = New-Object IO.FileStream($VulnerableJarFile, [IO.FileMode]::Open)
        $ZipArchiveMode = [IO.Compression.ZipArchiveMode]::Update
        $JarFile    = New-Object IO.Compression.ZipArchive($FileStream, $ZipArchiveMode)

        #Delete JndiLookup.class from jar-file
        ($JarFile.Entries | ? { $SearchString -contains $_.Name }) | % { $_.Delete() }

        #Cleanup/Close filehandles
        $JarFile.Dispose()
        $FileStream.Close()
        $FileStream.Dispose() 

        $ProcessedFiles = $processedFiles + ";"+ $VulnerableJarFile #-join ";"
    }  
}

#Remove trailing delimiter
$ProcessedFiles.Substring(1)
