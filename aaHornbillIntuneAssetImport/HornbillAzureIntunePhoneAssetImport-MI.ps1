<#PSScriptInfo
.VERSION 1.0.0
.GUID cb45bb07-b39b-4398-9903-4766c04c4cdf
.AUTHOR steve.goldthorpe@hornbill.com
.COMPANYNAME Hornbill
.TAGS hornbill powershell intune azure automation workflow runbook
.LICENSEURI https://wiki.hornbill.com/index.php/The_Hornbill_Community_License_(HCL)
.PROJECTURI https://github.com/hornbill/powershellHornbillAzureRunbooks
.ICONURI https://wiki.hornbill.com/skins/common/images/HBLOGO.png
.RELEASENOTES
Initial Release
.DESCRIPTION 
 Azure Automation Runbook to retrieve mobile assets from Intune, and import them into your Hornbill instance CMDB. 
 Modified to use native Graph PowerShell and user-assigned Managed Identity. Add an automation account variable for user-assigned managed identity client ID. Required graph API permission: DeviceManagementManagedDevices.Read.All
#>

#Requires -Module @{ModuleVersion = '1.1.0'; ModuleName = 'HornbillAPI'}
#Requires -Module @{ModuleVersion = '1.1.1'; ModuleName = 'HornbillHelpers'}

# Define Hornbill Params
$APIKey = "HornbillAPIKey" # Points to your Runbook variable that holds your Hornbill API Key
$InstanceID = "HornbillInstance" # Points to your Runbook variable that holds your Hornbill instance ID
$AssetClass = "mobileDevice" # Asset Class for Mobile Devices in your Hornbill instance
$AssetType = "77" # Primary Key for the "Smart Phone" asset type in your Hornbill instance
$AssetEntity = "AssetsMobileDevice" # Entity name of the Hornbill entity used to check for existing assets 
$AssetUniqueColumn = "h_serial_number" # Column in the above entity used to check for existing assets

#Import required modules
try {
    Import-Module -Name HornbillAPI -ErrorAction Stop -WarningAction silentlyContinue
    Import-Module -Name HornbillHelpers -ErrorAction Stop -WarningAction silentlyContinue
} catch {
    Write-Warning -Message "Failed to import modules"
}

#Read Creds and Vars
# $Credential = Get-AutomationPSCredential -Name $AutomationCred
# $AppClientID = Get-AutomationVariable -Name $AutomationVar
$APIKey = Get-AutomationVariable -Name $APIKey
$Instance = Get-AutomationVariable -Name $InstanceID
$ManagedIdentityClientId = Get-AutomationVariable -Name "ManagedIdentityClientId"

# Create Hornbill instance details
Set-HB-Instance -Instance $Instance -Key $APIKey

#region Connect MgGraph - with REST Access token
#Get auth token
try {
    if ($env:IDENTITY_ENDPOINT) {
        $res = "https://graph.microsoft.com/"
        $uri = "$($env:IDENTITY_ENDPOINT)?resource=$($res)&client_id=$($ManagedIdentityClientId)"
        $graphAccessToken = Invoke-RestMethod -Uri $uri -Method 'GET' -Headers @{'X-IDENTITY-HEADER' = "$env:IDENTITY_HEADER"; "Metadata" = "True" } -ContentType 'application/x-www-form-urlencoded'
        $env:graphToken = $graphAccessToken.access_token  
        $graphConnection = Connect-MgGraph -AccessToken $env:graphToken 
    }
    else {
        $settings = (Get-Content -Path ".\local.settings.json" | ConvertFrom-Json).Values 
        $graphConnection = Connect-MgGraph -ClientId $settings.ClientId -TenantId $settings.TenantId -CertificateThumbprint $settings.Thumbprint
        #Select-MgProfile -Name "v1.0" 
    }
    Write-Output "Connected Graph: $graphConnection" -Verbose

} catch [System.Exception] {
    Write-Warning -Message "Failed to retrieve auth token"
}
#endregion

$AssetsProcessed = @{
    "created" = 0
    "primaryupdated" = 0
    "relatedupdated" = 0
    "found" = 0
    "totalupdated" = 0
}

try {
    Write-Output "Retrieving managed devices"
    $ManagedDevices = Get-MgDeviceManagementManagedDevice -All 
    Write-Output "Managed device count: $($ManagedDevices.Count)"

    foreach ($Device in $ManagedDevices) {
        $AssetsProcessed.found++
        #Set Date/Time
        $CurrDateTime = Get-Date -format "yyyy/MM/dd HH:mm:ss"
        #Does asset exist?
        $AssetIDCheck = Get-HB-AssetID $Device.SerialNumber $AssetEntity $AssetUniqueColumn
        if( $null -ne $AssetIDCheck.AssetID) {
            Write-Output -InputObject ("Asset already exists, updating: " + $AssetIDCheck.AssetID)
            $UpdatedPrimary = $false
            $UpdatedRelated = $false
            #Asset Exists - Update Primary Entity Data First
            Add-HB-Param        "application" "com.hornbill.servicemanager"
            Add-HB-Param        "entity" "Asset"
            Add-HB-Param        "returnModifiedData" "true"
            Open-HB-Element     "primaryEntityData"
            Open-HB-Element     "record"
            Add-HB-Param        "h_pk_asset_id" $AssetIDCheck.AssetID
            Add-HB-Param        "h_class" $AssetClass
            Add-HB-Param        "h_asset_urn" ("urn:sys:entity:com.hornbill.servicemanager:Asset:"+$AssetIDCheck.AssetID)
            if($null -ne $Device.UserDisplayName -and $null -ne $Device.UserPrincipalName) {
                $OwnerURN = "urn:sys:0:" + $Device.UserDisplayName + ":" + $Device.UserPrincipalName
                Add-HB-Param        "h_owned_by" $OwnerURN
                Add-HB-Param        "h_owned_by_name" $Device.UserDisplayName
            }
            Add-HB-Param        "h_name" $Device.DeviceName
            Add-HB-Param        "h_description" $Device.ManagedDeviceName
            Close-HB-Element    "record"
            Close-HB-Element    "primaryEntityData"
            $UpdateAsset = Invoke-HB-XMLMC "data" "entityUpdateRecord"
        
            if($UpdateAsset.status -eq 'ok' -and $UpdateAsset.params.primaryEntityData.PSobject.Properties.name -match "record") {
                $UpdatedPrimary = $true
                $AssetsProcessed.primaryupdated++
                Write-Output -InputObject ("Asset Primary Record Updated: " + $AssetIDCheck.AssetID)
            } else {
                $ErrorMess = $UpdateAsset.error
                if($UpdateAsset.params.primaryEntityData.PSobject.Properties.name -notmatch "record") {
                    $ErrorMess = "There are no values to update" 
                }
                Write-Warning ("Error Updating Primary Asset Record " + $AssetIDCheck.AssetID + ": " + $ErrorMess)
            }
        
            # Now update related record information
            Add-HB-Param        "application" "com.hornbill.servicemanager"
            Add-HB-Param        "entity" "Asset"
            Add-HB-Param        "returnModifiedData" "true"
            Open-HB-Element     "primaryEntityData"
            Open-HB-Element     "record"
            Add-HB-Param        "h_pk_asset_id" $AssetIDCheck.AssetID
            Close-HB-Element    "record"
            Close-HB-Element    "primaryEntityData"
            Open-HB-Element     "relatedEntityData"
            Add-HB-Param        "relationshipName" "AssetClass"
            Add-HB-Param        "entityAction" "update"
            Open-HB-Element     "record"
            Add-HB-Param        "h_type" $AssetType
            Add-HB-Param        "h_capacity" $Device.TotalStorageSpaceInBytes
            Add-HB-Param        "h_description" $Device.ManagedDeviceName
            Add-HB-Param        "h_imei_number" $Device.Imei
            Add-HB-Param        "h_mac_address" $Device.WiFiMacAddress
            Add-HB-Param        "h_manufacturer" $Device.Manufacturer
            Add-HB-Param        "h_model" $Device.Model
            Add-HB-Param        "h_name" $Device.DeviceName
            Add-HB-Param        "h_os_version" ($Device.OperatingSystem + " " + $Device.OSVersion)
            Add-HB-Param        "h_phone_number" $Device.PhoneNumber
            Add-HB-Param        "h_serial_number" $Device.SerialNumber
            Close-HB-Element    "record"
            Close-HB-Element    "relatedEntityData"
            $UpdateAssetRelated = Invoke-HB-XMLMC "data" "entityUpdateRecord"
            if($UpdateAssetRelated.status -eq 'ok') {
                $UpdatedRelated = $true
                $AssetsProcessed.relatedupdated++
                Write-Output -InputObject ("Asset Related Record Updated: " + $AssetIDCheck.AssetID)
            } else {
                Write-Warning ("Error Updating Related Asset Record " + $AssetIDCheck.AssetID + ": " + $UpdateAssetRelated.error)
            }
        
            if($UpdatedPrimary -eq $true -or $UpdatedRelated -eq $true) {
                $AssetsProcessed.totalupdated++
                #Update Last Udated fields
                Add-HB-Param        "application" "com.hornbill.servicemanager"
                Add-HB-Param        "entity" "Asset"
                Open-HB-Element     "primaryEntityData"
                Open-HB-Element     "record"
                Add-HB-Param        "h_pk_asset_id" $AssetIDCheck.AssetID
                Add-HB-Param        "h_last_updated" $CurrDateTime
                Add-HB-Param        "h_last_updated_by" "Azure Intune Import"
                Close-HB-Element    "record"
                Close-HB-Element    "primaryEntityData"
                $UpdateLastAsset = Invoke-HB-XMLMC "data" "entityUpdateRecord"
                if($UpdateLastAsset.status -ne 'ok') {
                    Write-Warning ("Asset updated but error returned updating Last Updated values: " + $UpdateLastAsset.error)    
                }
            }
        
        } else {
            #Asset doesn't exist - Add
            Add-HB-Param        "application" "com.hornbill.servicemanager"
            Add-HB-Param        "entity" "Asset"
            Add-HB-Param        "returnModifiedData" "true"
            Open-HB-Element     "primaryEntityData"
            Open-HB-Element     "record"
            Add-HB-Param        "h_class" $AssetClass
            Add-HB-Param        "h_type" $AssetType
            Add-HB-Param        "h_last_updated" $CurrDateTime
            Add-HB-Param        "h_last_updated_by" "Azure Intune Import"
            if($null -ne $Device.UserDisplayName -and $null -ne $Device.UserPrincipalName) {
                $OwnerURN = "urn:sys:0:" + $Device.UserDisplayName + ":" + $Device.UserPrincipalName
                Add-HB-Param        "h_owned_by" $OwnerURN
                Add-HB-Param        "h_owned_by_name" $Device.UserDisplayName
            }
            Add-HB-Param        "h_name" $Device.DeviceName
            Add-HB-Param        "h_description" $Device.ManagedDeviceName
            Close-HB-Element    "record"
            Close-HB-Element    "primaryEntityData"
            Open-HB-Element     "relatedEntityData"
            Add-HB-Param        "relationshipName" "AssetClass"
            Add-HB-Param        "entityAction" "insert"
            Open-HB-Element     "record"
            Add-HB-Param        "h_type" $AssetType
            Add-HB-Param        "h_capacity" $Device.TotalStorageSpaceInBytes
            Add-HB-Param        "h_description" $Device.ManagedDeviceName
            Add-HB-Param        "h_imei_number" $Device.Imei
            Add-HB-Param        "h_mac_address" $Device.WiFiMacAddress
            Add-HB-Param        "h_manufacturer" $Device.Manufacturer
            Add-HB-Param        "h_model" $Device.Model
            Add-HB-Param        "h_name" $Device.DeviceName
            Add-HB-Param        "h_os_version" ($Device.OperatingSystem + " " + $Device.OSVersion)
            Add-HB-Param        "h_phone_number" $Device.PhoneNumber
            Add-HB-Param        "h_serial_number" $Device.SerialNumber
            Close-HB-Element    "record"
            Close-HB-Element    "relatedEntityData"
            $InsertAsset = Invoke-HB-XMLMC "data" "entityAddRecord"
            if($InsertAsset.status -eq 'ok') {
                $AssetsProcessed.created++
                Write-Output -InputObject ("Asset Imported: " + $InsertAsset.params.primaryEntityData.record.h_pk_asset_id)
                #Now update the asset with its URN
                Add-HB-Param        "application" "com.hornbill.servicemanager"
                Add-HB-Param        "entity" "Asset"
                Open-HB-Element     "primaryEntityData"
                Open-HB-Element     "record"
                Add-HB-Param        "h_pk_asset_id" $InsertAsset.params.primaryEntityData.record.h_pk_asset_id
                Add-HB-Param        "h_asset_urn" ("urn:sys:entity:com.hornbill.servicemanager:Asset:"+$InsertAsset.params.primaryEntityData.record.h_pk_asset_id)
                Close-HB-Element    "record"
                Close-HB-Element    "primaryEntityData"
                $UpdateAsset = Invoke-HB-XMLMC "data" "entityUpdateRecord"
                if($UpdateAsset.status -eq 'ok') {
                } else {
                    Write-Warning ("Error Updating Asset URN: " + $UpdateAsset.error)    
                }
        
            } else {
                Write-Warning ("Error Creating Asset: " + $InsertAsset.error)
            }
        }

    }
    
}
catch {
    Write-Warning "$($_.Exception.Message) ---> $($_.Exception.InnerException) ---> At Line number: $($_.InvocationInfo.ScriptLineNumber)" # Easy read error
    Write-Error $_.Exception # Writes to error stream    
    throw "Error caught. Aborting." # Fails runbook with Exception message
}

""
"IMPORT COMPLETE"
Write-Output -InputObject ("Assets Found:" + $AssetsProcessed.found)
Write-Output -InputObject ("Assets Created:" + $AssetsProcessed.created)
Write-Output -InputObject ("Assets Updated:" + $AssetsProcessed.created)
Write-Output -InputObject ("* Primary Record Updated:" + $AssetsProcessed.primaryupdated)
Write-Output -InputObject ("* Related Record Updated:" + $AssetsProcessed.relatedupdated)
