function GetLapsPassword
{
    param(
        [Parameter(Position = 0, Mandatory = $false)]
        [string]$ComputerName = "",
        [Parameter(Position = 1, Mandatory = $false)]
        [string]$ComputerList,
        [Parameter(Position = 2, Mandatory = $false)]
        [string]$OutFile = ""
    )
    # Function to get all OUs in the domain using LDAP queries
    function Get-AllOUs {
        $ouSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $ouSearcher.Filter = "(&(objectClass=organizationalUnit))"
        $ouSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $ouSearcher.PageSize = 1000
        $ouSearcher.PropertiesToLoad.Add("distinguishedName")
        $ouResults = $ouSearcher.FindAll()
        $ouList = foreach ($result in $ouResults) {
            [PSCustomObject]@{
                DistinguishedName = $result.Properties["distinguishedName"][0]
            }
        }
        return $ouList
    }
    # Function to resolve the SID to a readable name
    function Resolve-SIDToName {
        param (
            [Parameter(Position = 0, Mandatory = $true)]
            [string]$SID
        )
        try {
            $sidObject = New-Object System.Security.Principal.SecurityIdentifier($SID)
            $account = $sidObject.Translate([System.Security.Principal.NTAccount])
            return $account.Value
        } catch {
            return $SID
        }
    }
    # Function to check which users have ReadProperty permissions for ms-Mcs-AdmPwd
    function Get-UsersWithLapsPermission {
        param(
            [Parameter(Position = 0, Mandatory = $true)]
            [string]$OuDN
        )
        Write-Host "Checking ACLs for OU: $OuDN"
        # Create a DirectoryEntry object for the target OU
        $ouEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$OuDN")
        # Get the ACL for the OU
        $acl = $ouEntry.ObjectSecurity
        if ($acl.Access.Count -eq 0) {
            Write-Host "No ACLs found for OU: $OuDN" -ForegroundColor Yellow
        }
        $lapsPermissionUsers = @()
        foreach ($ace in $acl.Access) {
            if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight -and `
                $ace.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
                $resolvedName = Resolve-SIDToName -SID $ace.IdentityReference.Value
                $lapsPermissionUsers += [PSCustomObject]@{
                    IdentityReference = $resolvedName
                    AccessControlType = $ace.AccessControlType
                    ActiveDirectoryRights = $ace.ActiveDirectoryRights
                    ObjectType = $ace.ObjectType
                    InheritanceType = $ace.InheritanceType
                    IsInherited = $ace.IsInherited
                }
            }
        }
        return $lapsPermissionUsers
    }
    # Function to retrieve LAPS passwords
    function Get-LapsPasswords {
        param(
            [Parameter(Position = 0, Mandatory = $true)]
            [string]$OuDN
        )
        try {
            # Define the LDAP query for retrieving all computers in the selected OU
            $ldapQuery = "(&(objectClass=computer)(ms-Mcs-AdmPwdExpirationTime=*))"
            # Create a DirectorySearcher object
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$OuDN")
            $searcher.Filter = $ldapQuery
            $searcher.PageSize = 1000  # Set the page size for large queries
            # Specify the properties you want to retrieve, focusing only on ms-Mcs-AdmPwd for LAPS
            $searcher.PropertiesToLoad.AddRange(@("name", "ms-Mcs-AdmPwd"))
            # Perform the search
            $results = $searcher.FindAll()
            # Process the results
            $computers = foreach ($result in $results) {
                $properties = @{
                    Name = if ($result.Properties["name"]) { $result.Properties["name"][0] } else { $null }
                    LAPS_Password = if ($result.Properties["ms-Mcs-AdmPwd"]) { $result.Properties["ms-Mcs-AdmPwd"][0] } else { $null }
                }
                [PSCustomObject]$properties
            }
            return $computers
        }
        catch {
            Write-Error "Error retrieving LAPS passwords: $_"
            return $null
        }
    }
    # Enumerate all OUs
    $ous = Get-AllOUs
    # Display OUs
    $ous | ForEach-Object { Write-Host $_.DistinguishedName }
    # Get input from the user about the OU they want to enumerate
    $ouDN = Read-Host "Enter the distinguished name (DN) of the OU you want to enumerate"
    if (-not $ouDN) {
        Write-Host "No OU selected. Exiting."
        return
    }
    # Get users with LAPS permissions
    $lapsPermissionUsers = Get-UsersWithLapsPermission -OuDN $ouDN
    # Display users with LAPS permissions
    if ($lapsPermissionUsers.Count -gt 0) {
        $lapsPermissionUsers | Sort-Object -Property IdentityReference -Unique | Format-Table -AutoSize
    } else {
        Write-Host "No users found with permissions to read LAPS password."
    }
    # Get LAPS passwords for computers in the selected OU
    $computers = Get-LapsPasswords -OuDN $ouDN
    # Display the LAPS passwords
    if ($computers -ne $null) {
        $computers | Format-Table -AutoSize
    } else {
        Write-Host "No computers found with LAPS passwords."
    }
    # Optionally, output to file
    if ($OutFile) {
        $computers | Export-Csv -Path $OutFile -NoTypeInformation
    }
}
# Call the function
GetLapsPassword