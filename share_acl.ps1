# Description: This script will get all the permissions for all the folders on a server and export it to a JSON
$Report = @{}
$servers = "smdnas", "smdnas02"

# Extract Get-PathInfo into a function
function Get-PathInfo {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    $acl = Get-Acl -Path $Path

    # For each $acl.Access, if IsInherited is False, return the ACL
    return $acl.Access | ForEach-Object {
        if ($_.IsInherited -eq $false) {
            return [PSCustomObject]@{
                IdentityReference = $_.IdentityReference.ToString()
                AccessControlType = $_.AccessControlType.ToString()
                AccessControlTypeInt = [int]($_.AccessControlType)
                FileSystemRights = $_.FileSystemRights.ToString()
                FileSystemRightsInt = [int]($_.FileSystemRights)
                InheritanceFlagsInt = [int]$_.InheritanceFlags
                InheritanceFlags = $_.InheritanceFlags.ToString()
                PropagationFlags = $_.PropagationFlags.ToString()
                PropagationFlagsInt = [int]$_.PropagationFlags
            }
        }
    }
}

ForEach ($serverName in $servers) {
    $sharedFolders = (NET.EXE VIEW \\$serverName)

    ForEach ($folder in $sharedFolders) {
        # Ignore anything that is not a folder (comments, whitelines etc)
        if ($folder -notlike "*Disk*") {
            continue
        }
        # Remove Disk and everything thereafter, then trim whitespaces
        $folder = $folder.Substring(0, $folder.IndexOf("Disk")).Trim()

        $completePath = "\\$serverName\$folder"
        $Report[$completePath -replace '[^ -~\t]'] = @(Get-PathInfo($completePath))

        $sharePath = Get-ChildItem -Directory -Path $completePath -Force
        Foreach ($subfolder in $sharePath) {
            $completePathSub = "$completePath\$subfolder"
            $pathInfo = Get-PathInfo($completePathSub)
            # If pathInfo is not empty (some things not inherited), add it to the report
            if ($pathInfo) {
                $Report[$completePathSub -replace '[^ -~\t]'] = @($pathInfo)
            }
        }

    }
}

$Report | ConvertTo-JSON