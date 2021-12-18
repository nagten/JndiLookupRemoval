# JndiLookupRemoval
PowerShell script to Remove JndiLookup.class from Jar-files to remediate LOG4J Vulnerability (CVE-2021-44228 and
CVE-2021-45046). Script will use built-in compression library of Windows therefore no need to install 3rd party zip-utilities.

This PowerShell script will scan all Fixed local drives to discover potential vulnerable Jar-files that contain the JndiLookup class and remove it from the Jar-file, please patch to 2.17.0 or later as soon as possible to completely fix the vulnerability this is only a mitigation until application vendors release patches for their products.

See https://logging.apache.org/log4j/2.x/security.html

Implement one of the following mitigation techniques:

- Java 8 (or later) users should upgrade to release 2.16.0.
- Java 7 users should upgrade to release 2.12.2.
- Otherwise, in any release other than 2.16.0, you may remove the JndiLookup class from the classpath: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class

Requirements:

- Microsoft .NET Framework 4.5 or higher.

# Usage

Update variable $ExcludedFiles to include newer released versions that are not vulnerable

If one only wants to scan files that use LOG4J naming convention please comment line 40 and uncomment line 42 (-Include log4j-core-*.jar instead of -Include *.jar)

Run script .\JndiLookupRemoval.ps1

# Disclaimer

The code within this repository comes with no guarantee, the use of this code is your responsibility.

I take NO responsibility and/or liability for how you choose to use any of the source code available here. By using any of the files available in this repository, you understand that you are AGREEING TO USE AT YOUR OWN RISK. Once again, ALL files available here are for EDUCATION and/or RESEARCH purposes ONLY.
