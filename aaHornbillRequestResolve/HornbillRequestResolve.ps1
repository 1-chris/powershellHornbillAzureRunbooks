
<#PSScriptInfo

.VERSION 1.1.0

.GUID 2f62e163-3e2b-4842-acd1-4cb78ee1d290

.AUTHOR steve.goldthorpe@hornbill.com

.COMPANYNAME Hornbill

.TAGS hornbill powershell azure automation workflow runbook

.LICENSEURI https://wiki.hornbill.com/index.php/The_Hornbill_Community_License_(HCL)

.PROJECTURI https://github.com/hornbill/powershellHornbillAzureRunbooks

.ICONURI https://wiki.hornbill.com/skins/common/images/HBLOGO.png

.RELEASENOTES
Removed requirement to provide instanceZone param

.DESCRIPTION
 Azure Automation Runbook to resolve a Request within Service Manager on a Hornbill instance.

#>

#Requires -Module @{ModuleVersion = '1.1.0'; ModuleName = 'HornbillAPI'}
#Requires -Module @{ModuleVersion = '1.1.1'; ModuleName = 'HornbillHelpers'}

workflow Hornbill_RequestResolve_Workflow
{
    # Define Output stream type
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
        [string] $resolutionText,
        [string] $updateVisibility = "trustedGuest",
        [string] $closureCategoryId,
        [string] $closureCategoryName
    )

    # Define instance details
    Set-HB-Instance -Instance $instanceName -Key $instanceKey

    # Build timeline update JSON
    $timelineUpdate = '{"requestId":"'+$requestReference+'",'
    if($null -eq $closureCategoryName){
        $timelineUpdate += '"updateText":"Request has been resolved:\n\n'+ $resolutionText+'",'
    } else {
        $timelineUpdate += '"updateText":"Request has been resolved with the category: '+$closureCategoryName+'\n\n'+ $resolutionText+'",'
    }
    $timelineUpdate += '"activityType":"Resolve",'
    $timelineUpdate += '"source":"webclient",'
    $timelineUpdate += '"postType":"Resolve",'
    $timelineUpdate += '"visiblity":"'+$updateVisibility+'"}'

    # Add XMLMC params
    Add-HB-Param "requestId" $requestReference $false
    Add-HB-Param "resolutionText" $resolutionText $false
    Add-HB-Param "closureCategoryId" $closureCategoryId $false
    Add-HB-Param "closureCategoryName" $closureCategoryName $false
    Add-HB-Param "updateTimelineInputs" $timelineUpdate $false

    # Invoke XMLMC call, output returned as PSObject
    $xmlmcOutput = Invoke-HB-XMLMC "apps/com.hornbill.servicemanager/Requests" "resolveRequest"

    $exceptionName = ""
    $exceptionSummary = ""
    # Read output status
    if($xmlmcOutput.status -eq "ok") {
        if($xmlmcOutput.params.activityId -and $xmlmcOutput.params.activityId -ne ""){
            $activityId = $xmlmcOutput.params.activityId
        }
        if($xmlmcOutput.params.exceptionName -and $xmlmcOutput.params.exceptionName -ne ""){
            $exceptionName = $xmlmcOutput.params.exceptionName
            $exceptionSummary = $xmlmcOutput.params.exceptionDescription
        }
    }
    # Build resultObject to write to output
    $resultObject = New-Object PSObject -Property @{
        Status = $xmlmcOutput.status
        Error = $xmlmcOutput.error
        ActivityId = $activityId
        ExceptionName = $exceptionName
        ExceptionSummary = $exceptionSummary
    }

    if($resultObject.Status -ne "ok"){
        Write-Error $resultObject
    } else {
        if($resultOutput.ExceptionName -ne ""){
            Write-Warning $resultObject
        } else {
            Write-Output $resultObject
        }
    }
}