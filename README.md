# WIN_RenameDevice.ps1

## Description

`WIN_RenameDevice.ps1` is a PowerShell to rename Windows devices based on predefined naming conventions. The script leverages Microsoft Graph API to retrieve necessary information, such as Autopilot Group Tag details, was originally thought to be deployed via Intune Remediations or wrapped as Wind32 app for device managed and provisioned via Windows Autopilot and Microsoft Intune. I created it for a spceific Microsoft intune project, at the end I did not use it, instead I just simply used the Windows Autopilot "Device Name" property (filled in Device Name field in Autopilot Devices page).  

## Features

- **Microsoft Graph API Integration:** Authenticates and retrieves device information using Microsoft Graph API.
- **Certificate-Based Authentication:** Utilizes Intune client certificates for secure and automated authentication.
- **Custom Naming Conventions:** Constructs device names based on specific rules derived from Autopilot Group Tags.
- **Error Handling:** Includes robust error handling to ensure graceful script execution and logging.
- **Automation-Friendly:** Ideal for automated device management scenarios in enterprise environments.

## Prerequisites

1. **Microsoft Entra ID Registration:**
   - Devices must be registered in Windows Autopilot.
   - An Enterprise application must be registered in Azure AD with the following API permissions:
     - `Device.Read.All`
     - `DeviceManagementManagedDevices.Read.All`
     - `DeviceManagementManagedDevices.ReadWrite.All`
     - `User.Read`

2. **Certificates:**
   - The script uses Intune client certificates issued to devices by Microsoft Entra ID.
   - Ensure the device has the necessary Intune client certificate in the local machine's certificate store.

3. **Modules:**
   - Install the Microsoft Graph PowerShell SDK.
     ```powershell
     Install-Module Microsoft.Graph
     ```

## Parameters

- **tenantId**: The tenant ID for the Azure AD tenant.
- **clientId**: The client ID for the Azure AD application.

## Usage

### Example

```powershell
.\WIN_RenameDevice.ps1 -tenantId "your-tenant-id" -clientId "your-client-id"
```

## Workflow

  - **Locate Intune Client Certificate:** The script searches for the Intune client certificate in the local machine's certificate store using a part of the issuer's name.
  - **Authenticate to Microsoft Graph API:** Authenticates using the located certificate to access Microsoft Graph API.
  - **Retrieve Group Tag Information:** Retrieves the Autopilot Group Tag information for the device using Microsoft Graph API.
  - **Construct New Computer Name:** Constructs a new computer name based on extracted details from the Group Tag (e.g., building, department, device type).
  - **Rename Device:** Renames the device if the new name differs from the current name.
  - **Validates the renaming by checking the new name in the registry.**
  - **Schedules a shutdown to complete the renaming process.**

