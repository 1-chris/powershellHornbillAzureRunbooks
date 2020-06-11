
<#PSScriptInfo

.VERSION 1.1.0

.GUID 2b3d9b2a-2557-48a5-a3b0-68fb16c190d7

.AUTHOR steve.goldthorpe@hornbill.com

.COMPANYNAME Hornbill

.TAGS hornbill powershell azure automation workflow runbook

.LICENSEURI https://wiki.hornbill.com/index.php/The_Hornbill_Community_License_(HCL)

.PROJECTURI https://github.com/hornbill/powershellHornbillAzureRunbooks

.ICONURI https://wiki.hornbill.com/skins/common/images/HBLOGO.png

.RELEASENOTES
Removed requirement to provide instanceZone param

.DESCRIPTION
 Azure Automation Runbook to post an update to the timeline of a Request within Service Manager on a Hornbill instance.

#>

#Requires -Module @{ModuleVersion = '1.1.0'; ModuleName = 'HornbillAPI'}
#Requires -Module @{ModuleVersion = '1.1.1'; ModuleName = 'HornbillHelpers'}

workflow Hornbill_RequestUpdateTimeline_Workflow
{
    #Define Output Stream Type
    [OutputType([object])]
    # Define runbook input params
    Param
    (
        # Instance Connection Params
        [Parameter (Mandatory= $true)]
        [string] $instanceName,
        [Parameter (Mandatory= $true)]
        [string] $instanceKey,

        # API Params
        [Parameter (Mandatory= $true)]
        [string] $requestReference,
        [Parameter (Mandatory= $true)]
        [string] $content,
        [string] $action,
        [string] $source,
        [string] $extra,
        [string] $visibility = "trustedGuest",
        [string] $imageUrl,
        [string] $activityType
    )

    # Define instance details
    Set-HB-Instance -Instance $instanceName -Key $instanceKey


    # Add XMLMC params
    Add-HB-Param "requestId" $requestReference $false
    Add-HB-Param "action" $action $false
    Add-HB-Param "source" $source $false
    Add-HB-Param "content" $content $false
    Add-HB-Param "extra" $extra $false
    Add-HB-Param "visibility" $visibility $false
    Add-HB-Param "imageUrl" $imageUrl $false
    Add-HB-Param "activityType" $activityType $false

    # Invoke XMLMC call, output returned as PSObject
    $xmlmcOutput = Invoke-HB-XMLMC "apps/com.hornbill.servicemanager/Requests" "updateReqTimeline"

    # Read output status
    if($xmlmcOutput.status -eq "ok") {
        if($xmlmcOutput.params.activityId -and $xmlmcOutput.params.activityId -ne ""){
            $activityId = $xmlmcOutput.params.activityId
            $outcome = $xmlmcOutput.params.outcome
        }
    }
    # Build resultObject to write to output
    $resultObject = New-Object PSObject -Property @{
        Status = $xmlmcOutput.status
        Error = $xmlmcOutput.error
        ActivityId = $activityId
        Outcome = $outcome
    }

	if($resultObject.Status -ne "ok"){
        Write-Error $resultObject
    } else {
		Write-Output $resultObject
    }
}