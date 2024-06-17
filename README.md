# LAPS-Extractor

## Overview
Get-LapsPassword is a PowerShell script designed to retrieve LAPS (Local Administrator Password Solution) passwords for computers in an Active Directory environment. The script automates the process of querying organizational units (OUs) for computers with LAPS passwords and checking user permissions for reading these passwords.

## Features
Retrieve LAPS passwords for computers within specified OUs.
Enumerate all OUs in the domain using LDAP queries.
Check which users have ReadProperty permissions for ms-Mcs-AdmPwd.
Optionally output retrieved passwords to a specified file.

## Parameters
ComputerName (optional): Name of a single computer to query for the LAPS password.
ComputerList (optional): Path to a file containing a list of computer names.
OutFile (optional): Path to a file where retrieved LAPS passwords will be logged.

## Example Usage
### Retrieve LAPS passwords for all computers in a specified OU and output to a file
.\Get-LapsPassword.ps1 -ComputerList "C:\Path\To\ComputerList.txt" -OutFile "C:\Path\To\Output.csv"

## Contributing
Contributions are welcome! Please feel free to submit a pull request or open an issue for any improvements, bug fixes, or suggestions.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Credits
Author: https://www.linkedin.com/in/matan-bahar-66460a1b0/
