<#
.SYNOPSIS
    Changes the computer name based on Group Tag information which gets from Autopilot Group Tags.

.DESCRIPTION
    Script verifies the computer name to make sure it complies with a predefined naming convention. To comply with naming convention, information is gathered from Microsoft Entra ID by consulting Autopilot Group Tag. It authenticates to the Microsoft Graph API using a certificate provided by Microsoft Entra ID.

    For this process to work, the device must be registered in Windows Autopilot. Autopilot allows for the automatic provisioning and configuration of devices, ensuring they meet organizational standards from the outset. The script extracts relevant naming information from the Group Tag associated with the device's Entra ID.

    The script also requires an existing Enterprise application registered in Azure AD, with the necessary API permissions in Microsoft Graph. These permissions include:
    - Device.Read.All
    - DeviceManagementManagedDevices.Read.All
    - DeviceManagementManagedDevices.ReadWrite.All
    - User.Read

    The authentication is performed using certificates, specifically the "MS-Organization-Access certificate" provided by Microsoft Entra ID, it is specifically tied to device management scenarios managed through Intune.
    This certificate is unique to each device and is automatically provisioned as part of the Entra Join process and Intune Enrollment. Using this certificate simplifies administration and enhances security, it uses Entra ID,
    no need for additional certificate infrastrucutre, each device can authenticate independently and securely as long as it is Entra Joined.

    Upon execution, the script performs the following steps:
    1. Locates the EntraID/Intune client certificate in the local machine's certificate store.
    2. Authenticates to the Microsoft Graph API using the certificate.
    3. Retrieves the Group Tag information for the device.
    4. Constructs a new computer name based on specific rules defined in the script.
    5. Checks if the new name complies with the predefined naming convention.
    6. If the current computer name differs from the new name, renames the computer and schedules a shutdown to complete the renaming process.
    7. If the names are the same, no renaming is needed.

    The use of the EntraID/Intune client certificate ensures that each device can securely access the necessary resources in Microsoft Graph, facilitating the retrieval and application of Group Tag information. 

    Relevant sources and inspiration for this script include:
    - OOF Hours Blog: https://oofhours.com/2023/10/26/renaming-autopilot-deployed-devices/
    - Skotheimsvik Blog: https://skotheimsvik.no/rename-computers-with-countrycode-in-intune
    - Microsoft Graph API Documentation: https://docs.microsoft.com/en-us/graph/overview
    - PowerShell Microsoft Graph SDK Documentation: https://docs.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0

.PARAMETER tenantId
    The tenant ID for the Azure AD tenant.

.PARAMETER clientId
    The client ID for the Azure AD application.

.SOURCES
    - OOF Hours Blog: https://oofhours.com/2023/10/26/renaming-autopilot-deployed-devices/
    - Skotheimsvik Blog: https://skotheimsvik.no/rename-computers-with-countrycode-in-intune
    - Microsoft Graph API Documentation: https://docs.microsoft.com/en-us/graph/overview
    - PowerShell Microsoft Graph SDK Documentation: https://docs.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0

#>

param (
    [Parameter(Mandatory = $false)]
    [string]$tenantId = "your-default-tenant-id",

    [Parameter(Mandatory = $false)]
    [string]$clientId = "your-default-client-id"
)

# Check if mandatory parameters are provided
if (-not $PSBoundParameters.ContainsKey('tenantId') -or -not $PSBoundParameters.ContainsKey('clientId')) {
    # Display error message in red color
    Write-Host "Error: Missing mandatory parameters." -ForegroundColor Red
    Write-Host "Please provide the following parameters:" -ForegroundColor Red
    Write-Host "`t-tenantId: The tenant ID for the Azure AD tenant." -ForegroundColor Red
    Write-Host "`t-clientId: The client ID for the Azure AD application." -ForegroundColor Red
    exit 1
}

#Region Functions

# Tests for adminis priviliges 
function Test-AdminPrivileges {
    # Get the current Windows identity
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    # Check if the user is in the Administrators role
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script requires administrative privileges. Run it as an administrator."
    }
    else {
        Write-Host "Running with administrative privileges."
    }
}


function Get-IntuneClientCertificate {
    <#
    .SYNOPSIS
        Retrieves the thumbprint of a certificate from the local machine's certificate store.

    .DESCRIPTION
        It searches the local machine's certificate store for a client certificate issued by $issuePart (an expected string parameter), 
        for example, "MS-Organization-Access". If found, it returns the thumbprint of the certificate. If not found, it throws an error.

    .PARAMETER issuerPart
        A part of the issuer's name to search for in the certificate store (e.g., "MS-Organization-Access").

    .RETURNS
        The thumbprint of the Intune client certificate if found.

    .NOTES
        Ensure the script is run with administrative privileges to access the local machine's certificate store.

    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$issuerPart
    )
    try {
        # Open the certificate store for the local machine
        $certStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        $certStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        
        # Search for the certificate by part of the Issuer's name
        # Example issuerPart value: "MS-Organization-Access"
        $cert = $certStore.Certificates | Where-Object { $_.Issuer -like "*$issuerPart*" } | Select-Object -First 1
        
        # Close the certificate store
        $certStore.Close()
        
        # Check if the certificate was found
        if (-not $cert) {
            throw "Intune client certificate not found."
        }
        
        # Return the certificate thumbprint
        return $cert.Thumbprint
    } catch {
        # Handle errors by writing an error message and exiting with a non-zero status code
        # Throw an error message instead of exiting (I changed my mind)
        throw "Failed to retrieve Intune client certificate: $_"

    }
}

# Function to connect to Microsoft Graph using the certificate thumbprint
function Invoke-MgGraphConnect {
    <#
    .SYNOPSIS
        Connects to the Microsoft Graph API using a client certificate for authentication.

    .DESCRIPTION
        This function authenticates to the Microsoft Graph API using a client certificate. It requires the 
        tenant ID, client ID, and the thumbprint of the client certificate. The certificate must be registered 
        in the Azure AD application corresponding to the client ID. The function checks if the connection 
        was successful and throws an error if it fails.

    .PARAMETER tenantId
        The tenant ID for the EntraID (Azure AD) tenant. Specifies the directory where the authentication should take place.

    .PARAMETER clientId
        The client ID for the Azure AD application.

    .PARAMETER thumbprint
        The thumbprint of the client certificate used for authentication.
        The certificate must be registered in the EntraID application.

    .RETURNS
        Outputs a success message if the connection is established successfully.

    .NOTES
        Ensure that the Microsoft.Graph PowerShell module is installed.
        The EntraID application must have the required API permissions configured and granted admin consent.
        The client certificate must be correctly uploaded and associated with the Azure AD application.

    .EXAMPLE
        Invoke-MgGraphConnect -tenantId "your-tenant-id" -clientId "your-client-id" -thumbprint "your-certificate-thumbprint"
        This example connects to the Microsoft Graph API using the specified tenant ID, client ID, and certificate thumbprint.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$tenantId,

        [Parameter(Mandatory = $true)]
        [string]$clientId,

        [Parameter(Mandatory = $true)]
        [string]$thumbprint
    )
    try {
        # Connect to Microsoft Graph using the client ID, tenant ID, and certificate thumbprint
        Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $thumbprint -NoWelcome

        # Validate the connection using Get-MgContext
        # Get-MgContext retrieves the current context, including the token and authentication method
        $context = Get-MgContext

        # Check if the context is null or the token credential type is not ClientCertificate
        if ($null -eq $context -or $context.TokenCredentialType -ne "ClientCertificate") {
            throw "Failed to validate connection to Microsoft Graph."
        }

        # Output success message if connected successfully
        Write-Host "Successfully connected to Microsoft Graph."

    } catch {
        # Handle errors by writing an error message and exiting with a non-zero status code
        # Throw an error message instead of exiting ( Ichanged my mind)
        throw "Failed to connect to Microsoft Graph: $_"
    }
}

# Function to get IntuneDeviceID from the registry
function Get-IntuneDeviceId {
    <#
    .SYNOPSIS
        Retrieves the Intune Device ID from the local machine's registry for a given tenant ID.

    .DESCRIPTION
        It searches the registry on the local machine for Intune enrollment information.
        Identifies the most recent enrollment based on the timestamp and retrieves the associated Intune Device ID (EntDMID).
        The tenant ID is used to filter the relevant enrollment entries.

    .PARAMETER tenantId
        The tenant ID for the Azure Active Directory (Azure AD) tenant, 
           needed to filter the enrollment entries and ensure the correct Intune Device ID is retrieved.

    .RETURNS
        The Intune Device ID (EntDMID) associated with the given tenant ID.

    .NOTES
        Ensure the script is run with administrative privileges to access the local machine's registry.

    .EXAMPLE
        $deviceId = Get-IntuneDeviceId -tenantId "your-tenant-id"
        This example retrieves the Intune Device ID for the specified tenant ID.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$tenantId
    )
    try {
        # Base registry path where Intune enrollments are stored
        $baseRegistryPath = "HKLM:\SOFTWARE\Microsoft\Enrollments"
        
        # Retrieve all enrollment GUIDs (unique identifiers for each enrollment)
        $enrollmentGuids = Get-ChildItem -Path $baseRegistryPath | Where-Object { $_.PSIsContainer }
        
        # Initialize variables to track the latest timestamp and corresponding Intune Device ID
        $latestTimestamp = [DateTime]::MinValue
        $intuneDeviceId = $null

        # Loop through each enrollment GUID to find the one matching the tenant ID with the latest timestamp
        foreach ($guid in $enrollmentGuids) {
            try {
                # Get AADTenantID (Azure AD Tenant ID) for each enrollment GUID
                $aadTenantId = (Get-ItemProperty -Path "$baseRegistryPath\$($guid.PSChildName)" -Name "AADTenantID" -ErrorAction Stop).AADTenantID
            } catch {
                continue
            }

            # Check if the AADTenantID matches the provided tenant ID
            if ($aadTenantId -eq $tenantId) {
                try {
                    # Get the latest timestamp for the enrollment
                    $currentTimestampBinary = (Get-ItemProperty -Path "$baseRegistryPath\$($guid.PSChildName)\FirstSync" -Name "Timestamp" -ErrorAction Stop).Timestamp
                    $currentTimestamp = [System.BitConverter]::ToInt64($currentTimestampBinary, 0) -as [datetime]

                    # Update the latest timestamp and Intune Device ID if the current timestamp is more recent
                    if ($currentTimestamp -gt $latestTimestamp) {
                        $latestTimestamp = $currentTimestamp
                        $intuneDeviceId = (Get-ItemProperty -Path "$baseRegistryPath\$($guid.PSChildName)\DMClient\MS DM Server" -Name "EntDMID" -ErrorAction Stop).EntDMID
                    }
                } catch {
                    continue
                }
            }
        }

        # Check if the Intune Device ID was found
        if (-not $intuneDeviceId) {
            throw "IntuneDeviceID not found for Tenant ID: $tenantId."
        }

        # Return the Intune Device ID
        return $intuneDeviceId
    } catch {
        # Handle errors by writing an error message and exiting with a non-zero status code
        # Throw an error message instead of exiting (Changed my mind)
        throw "Failed to get IntuneDeviceID from registry: $_"
    }
}


# Function to get EntraID (azureADDeviceId) from Microsoft Graph API
function Get-EntraID {
    <#
    .SYNOPSIS
        Retrieves the "AzureADDeviceId" property from Microsoft Graph API using the Intune Device ID.

    .DESCRIPTION
        This function connects to the Microsoft Graph API to fetch details of a managed device using its Intune DeviceID.
        It retrieves the "AzureADDeviceId" from the device details. The function makes sure that a connection
        to Microsoft Graph is established before making the API request.

    .PARAMETER deviceId
        The Intune DeviceID of the managed device for which it should get the AzureDeviceID.

    .RETURNS
        The Azure AzureADDeviceId  associated with the provided Intune Device ID.

    .NOTES
        Ensure that the Microsoft.Graph PowerShell module is installed and imported.
        The function requires an active connection to Microsoft Graph API established using appropriate credentials.

    .EXAMPLE
        $entraID = Get-EntraID -deviceId "your-intune-device-id"
        This example retrieves the AzureADDeviceId for the specified Intune Device ID.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$deviceId
    )
    try {
        # URI to get device details from Microsoft Graph API
        $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$deviceId"
        
        # Ensure the connection to Microsoft Graph is established
        $context = Get-MgContext
        if (-not $context) {
            throw "Not connected to Microsoft Graph. Please establish a connection first."
        }

        # Send the request to Microsoft Graph API to get device details
        $deviceDetails = Invoke-MgGraphRequest -Uri $uri -Method Get

        # Check if the device details contain the azureADDeviceId
        if ($deviceDetails.azureADDeviceId) {
            # Return the AzureADDeviceId property
            return $deviceDetails.azureADDeviceId
        } else {
            throw "azureADDeviceId not found for device ID: $deviceId."
        }
    } catch {
        # Handle errors by writing an error message and exiting with a non-zero status code
        # Throw an error message instead of exiting (Changed my mind)
        throw "Failed to get azureADDeviceId from Microsoft Graph: $_"
    }
}


# Function to get Group Tag information using EntraID (azureADDeviceId)
function Get-GroupTag {
    <#
    .SYNOPSIS"
        Retrieves the Autopilot "Group Tag" information for a device using its EntraID ("AzureADDeviceId") from Microsoft Graph API.

    .DESCRIPTION
        This function connects to the Microsoft Graph API to fetch device details using the Azure AD Device ID.
        Then retrieves the Group Tag information from the device details. The function ensures that a connection
        to Microsoft Graph is established before making the API request.

    .PARAMETER entraID
        The Azure AD Device ID of the device.

    .RETURNS
        The Group Tag (OrderId) associated with the provided Azure AD Device ID.

    .NOTES
        Ensure that the Microsoft.Graph PowerShell module is installed and imported.
        The function requires an active connection to Microsoft Graph API established using appropriate credentials.

    .EXAMPLE
        $groupTag = Get-GroupTag -entraID "your-azure-ad-device-id"
        This example retrieves the Group Tag for the specified Azure AD Device ID.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$entraID
    )
    try {
        # URI to get device details from Microsoft Graph with filtering
        $uri = "https://graph.microsoft.com/v1.0/devices"
        $uriFiltered = "$uri" + "?" + "`$filter=deviceID eq '$entraID'"

        # Ensure the connection to Microsoft Graph is established
        $context = Get-MgContext
        if (-not $context) {
            throw "Not connected to Microsoft Graph. Please establish a connection first."
        }

        # Send the request to Microsoft Graph API to get the device details
        $deviceDetails = Invoke-MgGraphRequest -Uri $uriFiltered -Method Get

        # Check if the request returned any device details
        if ($deviceDetails.value -and $deviceDetails.value.Count -gt 0) {
            # Convert the first device's details to JSON and back to a PowerShell object for easier access
            $device = $deviceDetails.value[0] | ConvertTo-Json # Much easier to read while debugging, then just lef it there :)
            $device = $device | ConvertFrom-Json

            # Check if the device has physicalIds and look for the Group Tag (OrderId)
            if ($device.physicalIds) {
                foreach ($physicalId in $device.physicalIds) {
                    if ($physicalId -match "\[OrderId\]:.*") {
                        # Return the Group Tag (OrderId)
                        return $physicalId
                    }
                }
                throw "OrderId not found in physicalIds for EntraID: $entraID."
            } else {
                throw "physicalIds not found for EntraID: $entraID."
            }
        } else {
            throw "Device not found for EntraID: $entraID."
        }
    } catch {
        # Handle errors by writing an error message and exiting with a non-zero status code
        # Throw an error message instead of exiting (Change my mind)
        throw "Failed to get Group Tag information from Microsoft Graph: $_"
    }
}


# Function to rename the computer and schedule a shutdown
function Rename-ComputerAndShutdown {
    <#
    .SYNOPSIS
        Renames the computer to a specified new name and schedules a shutdown.

    .DESCRIPTION
        This function renames the computer using a new name provided as a parameter.
        It validates that the script is running with administrative privileges, changes the computer name,
        verifies the change in the registry, and schedules a shutdown. The function ensures that the
        computer name does not exceed 15 characters and handles errors gracefully by throwing exceptions.

    .PARAMETER newName
        The new name for the computer. The name should not exceed 15 characters.

    .RETURNS
        Outputs a message indicating the success or failure of the operation.

    .NOTES
        Ensure the script is run with administrative privileges to change the computer name and access the registry.

    .EXAMPLE
        Rename-ComputerAndShutdown -newName "NewCompName"
        This example renames the computer to "NewCompName" and schedules a shutdown in 10 minutes.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$newName
    )

    try {
        # Check if the script is running with administrative privileges
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "Administrative privileges are required to change the computer name."
        }

        # Get the current computer name
        $currentName = (Get-CimInstance -ClassName Win32_ComputerSystem).Name

        # Truncate the new name to 15 characters, 
        if ($newName.Length -gt 15) {
            $newName = $newName.Substring(0, 15)
        }

        # Check if the new name is the same as the current name
        if ($currentName -eq $newName) {
            Write-Host "The current computer name and the new computer name are the same. No change needed."
            return
        }

        # Change the computer name
        Rename-Computer -NewName $newName -Force -Restart:$false

        # Validate the new computer name in the registry
        Start-Sleep -Seconds 5 # Wait for a few seconds to ensure the registry is updated
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"
        $newComputerName = (Get-ItemProperty -Path $registryPath).ComputerName

        if ($newComputerName -ne $newName) {
            throw "The computer name in the registry does not match the new name."
        }

        # Schedule a shutdown in 10 minutes
        shutdown.exe /s /t 600
        Write-Host "Computer will shutdown in 10 minutes."

    } catch {
        # Handle errors by throwing an error message to be caught by the main script
        throw "Error occurred while trying to rename the device: $_"
    }
}


function WriteAndExitWithSummary {
    <#
    .SYNOPSIS
        Writes a summary of the script's execution to the console and then exits the script with a specified status code.

    .DESCRIPTION
        This function takes a status code and a summary string as parameters. It writes the summary along with the current date and time to the console using Write-Host. 
        After writing the summary, it exits the script with the given status code. If the given status code is below 0 (negative) it changes exit status code to 0

    .PARAMETER StatusCode
        The exit status code to be used when exiting the script. 
        0: OK
        1: TpmPin Found
        Other: WARNING

    .PARAMETER Summary
        The summary string that describes the script's execution status. This will be written to the console.

    .EXAMPLE
        WriteAndExitWithSummary -StatusCode 0 -Summary "All volumes checked, no TpmPin found."
        Writes "All volumes checked, no TpmPin found." along with the current date and time to the console and exits with status code 0.

    .EXAMPLE
        WriteAndExitWithSummary -StatusCode 1 -Summary "TpmPin found on volume C:."
        Writes "TpmPin found on volume C:." along with the current date and time to the console and exits with status code 1.

    .NOTES
        Last Modified: August 27, 2023
        Author: Manuel Nieto
    #>

    param (
        [int]$StatusCode,
        [string]$Summary
    )
    
    # Combine the summary with the current date and time.
    $finalSummary = "$([datetime]::Now) = $Summary"
    
    # Determine the prefix based on the status code.
    $prefix = switch ($StatusCode) {
        0 { "OK" }
        1 { "FAIL" }
        default { "WARNING" }
    }
    
    # Easier to read in log file
    Write-Host "`n`n"

    # Write the final summary to the console.
    Write-Host "$prefix $finalSummary"
    
    # Easier to read in log file
    Write-Host "`n`n"

    # Exit the script with the given status code.
    if ($StatusCode -lt 0) {$StatusCode = 0}
    Exit $StatusCode
}


#Endregion

#Region Main

# Variables used in the Main section
$issuerPart = "CN=MS-Organization-Access"  # Part of the issuer's name to identify Entra or Intune client certificate
$thumbprint = ""                           # Thumbprint of the Intune client certificate
$deviceId = ""                             # Intune Device ID retrieved from the registry
$entraID = ""                              # Azure AD Device ID retrieved from Microsoft Graph
$groupTag = ""                             # Group Tag information retrieved from Microsoft Graph
$tagAfterColon = ""                        # Part of the Group Tag after the colon
$assetId = ""                              # Asset ID extracted from the Group Tag
$building = ""                             # Building extracted from Group Tag
$department = ""                           # Department extracted from the Group Tag
$type = ""                                 # Device Type extracted from the Group Tag
$execStatus = 0                            # Status of the script execution (0 = OK, 1 = FAIL, other = WARNING)
$execSummary = ""                          # Summary of the script execution

# Easier to read in log file
Write-Host "`n`n"

# Verifying permissions before we begging anything else.
try {
    Test-AdminPrivileges
    # The rest of your script goes here
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}

# Issuer part to identify the Intune client certificate
$issuerPart = "CN=MS-Organization-Access"


try {
    # Retrieve the certificate thumbprint
    $thumbprint = Get-IntuneClientCertificate -issuerPart $issuerPart
    $execSummary += "Cert found. "
} catch {
    $execStatus = 1
    $execSummary += "Cert not found. "
    WriteAndExitWithSummary -StatusCode $execStatus -Summary $execSummary
}

try {
    # Connect to Microsoft Graph
    Invoke-MgGraphConnect -tenantId $tenantId -clientId $clientId -thumbprint $thumbprint
    $execSummary += "Graph connected. "
} catch {
    $execStatus = 1
    $execSummary += "Graph connection error. "
    WriteAndExitWithSummary -StatusCode $execStatus -Summary $execSummary
}

try {
    # Get Intune Device ID from the registry
    $deviceId = Get-IntuneDeviceId -tenantId $tenantId
    $execSummary += "Intune Device ID found. "
} catch {
    $execStatus = 1
    $execSummary += "Intune Device ID not found. "
    WriteAndExitWithSummary -StatusCode $execStatus -Summary $execSummary
}

try {
    # Get EntraID (Azure AD Device ID) from Microsoft Graph
    $entraID = Get-EntraID -deviceId $deviceId
    $execSummary += "EntraID found. "
} catch {
    $execStatus = 1
    $execSummary += "EntraID not found. "
    WriteAndExitWithSummary -StatusCode $execStatus -Summary $execSummary
}

try {
    # Get Group Tag information from Microsoft Graph
    $groupTag = Get-GroupTag -entraID $entraID
    $execSummary += "Group Tag found. "
    Write-Host "Group Tag for the device: $groupTag"
} catch {
    $execStatus = 1
    $execSummary += "Group Tag not found. "
    WriteAndExitWithSummary -StatusCode $execStatus -Summary $execSummary
}

# =================================
# Change Here.
# =================================
<#
.DESCRIPTION
    The following section of the script constructs a new computer name based on specific parameters extracted from a Group Tag.
    This part of the script is for a unique use case in a particular project. 

    For this specific project:
    - The building information is extracted from the 5th segment from the end.
    - The department is extracted from the 4th segment from the end.
    - The device type is extracted from the 2nd segment from the end.

    These specific lines of code are likely to be different for others interested in using this code. Users should modify this 
    section according to their own requirements and the structure of their Group Tags or naming conventions. The new name 
    constructed here is an example of how to parse and use parts of a string to form a meaningful and specific computer name 
    for a particular environment. 
    
    This should be adapted to fit naming conventions, organizational requirements, etc.
    Adjust the indices and logic accordingly to match your specific needs.
#>
try {
    # Extract information from the Group Tag
    $tagAfterColon = $groupTag.Split(":")[1].Trim()

    # Extracting the last segment before the dash for AssetId
    $segments = $tagAfterColon.Split("-")
    $assetId = $segments[-1]

    # Validate that the assetId contains only digits
    if (-not $assetId -match '^\d+$') {
        throw "Asset ID contains non-digit characters."
    }

    # Extracting the Building information.
    $buildingIndex = -5
    $building = $segments[$buildingIndex]

    # Extracting the department (characters between 4th and 5th dash from last to first)
    $departmentIndex = -4
    $department = $segments[$departmentIndex]

    # Extracting the type (characters between the dash before last and last dash)
    $typeIndex = -2
    $type = $segments[$typeIndex]

    Write-Host "Asset ID: $assetId"
    Write-Host "Building: $building"
    Write-Host "Department: $department"
    Write-Host "Device Type: $type"
    $execSummary += "Info extracted $tagAfterColon. "

} catch {
    $execStatus = 1
    $execSummary += "Info extraction failed. "
    WriteAndExitWithSummary -StatusCode $execStatus -Summary $execSummary
}

# Determine the new computer name based on the extracted information.
# This is actually done in Rename-ComputerAndShutdown, repeated here just for the purpose of logging.
$currentName = (Get-CimInstance -ClassName Win32_ComputerSystem).Name
$newName = if ($building.Length -gt 3) { $building.Substring(0, 3) } else { $building }
$newName += if ($department.Length -gt 3) { $department.Substring(0, 3) } else { $department }
$newName += $type.Substring(0, 1)
$newName += $assetId
#Truncate new name to 15 characters
if ($newName.Length -gt 15) {
    $newName = $newName.Substring(0, 15)
}

# =================================

try {
    # Check if a rename is necessary and update the summary
    if ($currentName -eq $newName) {
        Write-Host "The current computer name and the new computer name are the same. No change needed."
        $execSummary += "No rename needed. "
    } else {
        # Rename the computer and schedule a shutdown (restart)
        Rename-ComputerAndShutdown -newName $newName
        $execSummary += "Renamed to $newName, scheduled shutdown. "
    }
} catch {
    $execStatus = 1
    $execSummary += "Rename or shutdown failed. "
    WriteAndExitWithSummary -StatusCode $execStatus -Summary $execSummary
}

WriteAndExitWithSummary -StatusCode $execStatus -Summary $execSummary

#Endregion
