#!/usr/bin/env pwsh

#=========================================================================
# Script: Security Assessment Tool
# Purpose: Performs security assessments on domains using CrowdStrike API
#=========================================================================

[CmdletBinding()]
param ()

Clear-Host

#-------------------------------------------------------------------------
# Directory Setup
#-------------------------------------------------------------------------
$ScriptDirectory = $PWD.Path

# Create Logs directory if it doesn't exist
$LogsDirectory = Join-Path -Path $ScriptDirectory -ChildPath "Logs"
if (-not (Test-Path -Path $LogsDirectory)) {
    New-Item -ItemType Directory -Path $LogsDirectory -Force | Out-Null
}

# Initialize logging with full path
$LogFileName = "SecurityAssessment_$(Get-Date -Format 'ddMMyyyy_HHmmss').log"
$Global:LogPath = Join-Path -Path $LogsDirectory -ChildPath $LogFileName

#-------------------------------------------------------------------------
# Logging Function
#-------------------------------------------------------------------------
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    try {
        $Timestamp = Get-Date -Format "dd-MM-yyyy HH:mm:ss"
        $LogMessage = "[$Timestamp] [$Level] $Message"
        
        switch ($Level) {
            'Info'    { Write-Host $LogMessage -ForegroundColor Green }
            'Warning' { Write-Host $LogMessage -ForegroundColor Yellow }
            'Error'   { Write-Host $LogMessage -ForegroundColor Red }
        }
        
        Add-Content -Path $Global:LogPath -Value $LogMessage
    }
    catch {
        Write-Host "Failed to write to log: $_" -ForegroundColor Red
    }
}

#-------------------------------------------------------------------------
# CrowdStrike Region Configuration
#-------------------------------------------------------------------------
function Initialize-CrowdStrikeRegions {
    return @{
        '1' = @{ Name = 'US-1'; Url = 'https://api.crowdstrike.com' }
        '2' = @{ Name = 'US-2'; Url = 'https://api.us-2.crowdstrike.com' }
        '3' = @{ Name = 'EU-1'; Url = 'https://api.eu-1.crowdstrike.com' }
        '4' = @{ Name = 'US-GOV-1'; Url = 'https://api.laggar.gcw.crowdstrike.com' }
    }
}

#-------------------------------------------------------------------------
# Region Selection
#-------------------------------------------------------------------------
function Get-UserRegionSelection {
    param (
        [hashtable]$Regions
    )
    
    Write-Log "Starting region selection process"
    Write-Host "`nSelect a CrowdStrike API region:" -ForegroundColor Cyan
    
    $SortedKeys = $Regions.Keys | Sort-Object
    foreach ($Key in $SortedKeys) {
        Write-Host "$Key. $($Regions[$Key].Name)"
    }
    
    do {
        $RegionChoice = Read-Host "`nEnter the number corresponding to your region"
        if (-not $Regions.ContainsKey($RegionChoice)) {
            Write-Log "Invalid region selection: $RegionChoice" -Level Warning
            Write-Host "Invalid selection. Please try again." -ForegroundColor Yellow
        }
    } while (-not $Regions.ContainsKey($RegionChoice))
    
    Write-Log "Selected region: $($Regions[$RegionChoice].Name)"
    return $Regions[$RegionChoice]
}

#-------------------------------------------------------------------------
# Authentication
#-------------------------------------------------------------------------
function Get-CrowdStrikeToken {
    param (
        [string]$BaseUrl
    )
    
    try {
        $ApiClientId = Read-Host "Enter your API Client ID"
        $ApiClientSecret = Read-Host "Enter your API Client Secret" -AsSecureString
        $ApiClientSecretPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiClientSecret)
        )
        
        Write-Log "Attempting to obtain OAuth2 token"
        $TokenResponse = Invoke-RestMethod -Method POST -Uri "$BaseUrl/oauth2/token" -Headers @{
            'Content-Type' = 'application/x-www-form-urlencoded'
        } -Body "client_id=$ApiClientId&client_secret=$ApiClientSecretPlainText"
        
        if (-not $TokenResponse.access_token) {
            throw "No access token received in response"
        }
        
        Write-Log "Successfully obtained OAuth2 token"
        return $TokenResponse.access_token
    }
    catch {
        Write-Log "Failed to obtain OAuth2 token: $_" -Level Error
        throw
    }
    finally {
        # Clear sensitive data from memory
        $ApiClientSecret = $null
        $ApiClientSecretPlainText = $null
        [System.GC]::Collect()
    }
}

#-------------------------------------------------------------------------
# Domain List Retrieval
#-------------------------------------------------------------------------
function Get-DomainList {
    param (
        [string]$BaseUrl,
        [string]$AccessToken
    )
    
    try {
        Write-Log "Fetching domain list"
        
        $GraphQLQuery = @"
{
    domains(dataSources: [])
}
"@
        
        $GraphQLResponse = Invoke-RestMethod -Method POST -Uri "$BaseUrl/identity-protection/combined/graphql/v1" `
            -Headers @{
                'Authorization' = "Bearer $AccessToken"
                'Content-Type' = 'application/json'
            } `
            -Body (@{ query = $GraphQLQuery } | ConvertTo-Json)
        
        if (-not $GraphQLResponse.data.domains) {
            Write-Log "No domains returned from API" -Level Warning
            return @()
        }
        
        Write-Log "Successfully retrieved domain list"
        return $GraphQLResponse.data.domains
    }
    catch {
        Write-Log "Error fetching domain list: $_" -Level Error
        throw
    }
}

#-------------------------------------------------------------------------
# Security Assessment
#-------------------------------------------------------------------------
function Get-SecurityAssessment {
    param (
        [string]$Domain,
        [string]$BaseUrl,
        [string]$AccessToken
    )
    
    try {
        Write-Log "Querying security assessment for domain: $Domain"
        
        $GraphQLQuery = @"
{
    securityAssessment(domain: "$Domain") {
        overallScore
        overallScoreLevel
        assessmentFactors {
            riskFactorType
            severity
            likelihood
        }
    }
}
"@
        
        $GraphQLResponse = Invoke-RestMethod -Method POST -Uri "$BaseUrl/identity-protection/combined/graphql/v1" `
            -Headers @{
                'Authorization' = "Bearer $AccessToken"
                'Content-Type' = 'application/json'
            } `
            -Body (@{ query = $GraphQLQuery } | ConvertTo-Json -Depth 3)
        
        if (-not $GraphQLResponse.data) {
            Write-Log "No data returned for domain: $Domain" -Level Warning
            return $null
        }
        
        return $GraphQLResponse.data.securityAssessment
    }
    catch {
        Write-Log "Error querying domain $Domain`: $_" -Level Error
        return $null
    }
}

#-------------------------------------------------------------------------
# Generic Entity Query Function
#-------------------------------------------------------------------------
function Get-EntityData {
    param (
        [string]$BaseUrl,
        [string]$AccessToken,
        [string]$QueryParameter,
        [string]$AfterCursor = $null
    )
    
    try {
        $GraphQLQuery = @"
{
    entities(
        $QueryParameter
        archived: false
        first: 1000
        $(if($AfterCursor){"after: `"$AfterCursor`""})
    ) {
        pageInfo {
            hasNextPage
            endCursor
        }
        nodes {
            primaryDisplayName
            secondaryDisplayName
            isHuman: hasRole(type: HumanUserAccountRole)
            isProgrammatic: hasRole(type: ProgrammaticUserAccountRole)
            riskScore
            riskScoreSeverity
        }
    }
}
"@
        
        $GraphQLResponse = Invoke-RestMethod -Method POST -Uri "$BaseUrl/identity-protection/combined/graphql/v1" `
            -Headers @{
                'Authorization' = "Bearer $AccessToken"
                'Content-Type' = 'application/json'
            } `
            -Body (@{ query = $GraphQLQuery } | ConvertTo-Json -Depth 3)
        
        return $GraphQLResponse.data.entities
    }
    catch {
        Write-Log "Error querying entities: $_" -Level Error
        return $null
    }
}

#-------------------------------------------------------------------------
# Data Export
#-------------------------------------------------------------------------
function Export-AssessmentData {
    param (
        [Array]$Data,
        [string]$OutputPath,
        [string]$FilePrefix
    )
    
    try {
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        
        $CsvPath = Join-Path $OutputPath "${FilePrefix}_$(Get-Date -Format 'ddMMyyyy_HHmmss').csv"
        $Data | ConvertTo-Csv -NoTypeInformation | ForEach-Object {
            [System.Text.Encoding]::UTF8.GetBytes("$_`r`n")
        } | Set-Content -Path $CsvPath -Encoding Byte
        Write-Log "Successfully exported CSV to: $CsvPath"
        
        $JsonPath = Join-Path $OutputPath "${FilePrefix}_$(Get-Date -Format 'ddMMyyyy_HHmmss').json"
        $JsonContent = $Data | ConvertTo-Json -Depth 3
        [System.IO.File]::WriteAllText($JsonPath, $JsonContent, [System.Text.Encoding]::UTF8)
        Write-Log "Successfully exported JSON to: $JsonPath"
    }
    catch {
        Write-Log "Error exporting data: $_" -Level Error
        throw
    }
}

#-------------------------------------------------------------------------
# Entity Query Menu
#-------------------------------------------------------------------------
function Show-EntityQueryMenu {
    param (
        [string]$BaseUrl,
        [string]$AccessToken
    )
    
    $menuOptions = @{
        1 = @{
            'Parameter' = 'accountLocked'
            'Description' = 'Find locked accounts'
        }
        2 = @{
            'Parameter' = 'cloudEnabled'
            'Description' = 'Find accounts with SSO enabled'
        }
        3 = @{
            'Parameter' = 'cloudOnly'
            'Description' = 'Find cloud-only accounts'
        }
        4 = @{
            'Parameter' = 'hasAgedPassword'
            'Description' = 'Find accounts with old passwords'
        }
        5 = @{
            'Parameter' = 'hasAgent'
            'Description' = 'Find accounts with Falcon sensor'
        }
        6 = @{
            'Parameter' = 'hasExposedPassword'
            'Description' = 'Find accounts with exposed passwords'
        }
        7 = @{
            'Parameter' = 'hasNeverExpiringPassword'
            'Description' = 'Find accounts with non-expiring passwords'
        }
        8 = @{
            'Parameter' = 'hasOpenIncidents'
            'Description' = 'Find accounts with open incidents'
        }
        9 = @{
            'Parameter' = 'hasVulnerableOs'
            'Description' = 'Find endpoints with vulnerable OS'
        }
        10 = @{
            'Parameter' = 'hasWeakPassword'
            'Description' = 'Find accounts with weak passwords'
        }
        11 = @{
            'Parameter' = 'inactive'
            'Description' = 'Find inactive accounts'
        }
        12 = @{
            'Parameter' = 'learned'
            'Description' = 'Find learned entities'
        }
        13 = @{
            'Parameter' = 'marked'
            'Description' = 'Find marked entities'
        }
        14 = @{
            'Parameter' = 'shared'
            'Description' = 'Find shared accounts'
        }
        15 = @{
            'Parameter' = 'stale'
            'Description' = 'Find stale accounts'
        }
        16 = @{
            'Parameter' = 'unmanaged'
            'Description' = 'Find unmanaged endpoints'
        }
        17 = @{
            'Parameter' = 'watched'
            'Description' = 'Find watched entities'
        }
    }
    
    do {
        Write-Host "`nEntity Query Options:" -ForegroundColor Cyan
        foreach ($key in $menuOptions.Keys | Sort-Object) {
            Write-Host "$key. $($menuOptions[$key].Description)"
        }
        Write-Host "18. Exit to Main Menu"
        
        $choice = Read-Host "`nEnter your choice (1-18)"
        
        if ($choice -eq '18') {
            return
        }
        elseif ($menuOptions.ContainsKey([int]$choice)) {
            $selectedOption = $menuOptions[[int]$choice]
            Write-Host "Processing query: $($selectedOption.Description)"
            
            $Data = @()
            $hasNextPage = $true
            $afterCursor = $null
            $pageCount = 1
            
            Write-Host "Fetching entities..."
            while ($hasNextPage) {
                Write-Host "Fetching page $pageCount"
                $QueryParam = "$($selectedOption.Parameter):true"
                $Response = Get-EntityData -BaseUrl $BaseUrl -AccessToken $AccessToken -QueryParameter $QueryParam -AfterCursor $afterCursor
                
                if ($Response) {
                    $Data += $Response.nodes
                    $hasNextPage = $Response.pageInfo.hasNextPage
                    $afterCursor = $Response.pageInfo.endCursor
                    $pageCount++
                }
                else {
                    $hasNextPage = $false
                }
                Start-Sleep -Milliseconds 100
            }
            
            if ($Data.Count -eq 0) {
                Write-Log "No entities found for the selected query" -Level Warning
            }
            else {
                $OutputPath = Join-Path $ScriptDirectory "Output"
                Export-AssessmentData -Data $Data -OutputPath $OutputPath -FilePrefix "EntityQuery_$($selectedOption.Parameter)"
            }
        }
        else {
            Write-Host "Invalid choice. Please try again." -ForegroundColor Yellow
        }
    } while ($true)
}

#-------------------------------------------------------------------------
# Main Execution Block
#-------------------------------------------------------------------------
try {
    Write-Log "Script execution started"
    
    $Regions = Initialize-CrowdStrikeRegions
    $SelectedRegion = Get-UserRegionSelection -Regions $Regions
    $AccessToken = Get-CrowdStrikeToken -BaseUrl $SelectedRegion.Url
    
    do {
        Write-Host "`nSelect an option:" -ForegroundColor Cyan
        Write-Host "1. Get Domain Risks"
        Write-Host "2. Entities Query"
        Write-Host "3. Exit"
        
        $choice = Read-Host "`nEnter your choice (1-3)"
        
        switch ($choice) {
            "1" {
                $Data = @()
                $DomainList = Get-DomainList -BaseUrl $SelectedRegion.Url -AccessToken $AccessToken
                
                foreach ($Domain in $DomainList) {
                    $Assessment = Get-SecurityAssessment -Domain $Domain -BaseUrl $SelectedRegion.Url -AccessToken $AccessToken
                    
                    if ($Assessment) {
                        foreach ($Factor in $Assessment.assessmentFactors) {
                            $Data += [PSCustomObject]@{
                                Domain = $Domain
                                RiskFactorType = $Factor.riskFactorType
                                Severity = $Factor.severity
                                Likelihood = $Factor.likelihood
                                OverallScore = $Assessment.overallScore
                                OverallScoreLevel = $Assessment.overallScoreLevel
                            }
                        }
                    }
                }
                
                if ($Data.Count -eq 0) {
                    Write-Log "No assessment data was collected" -Level Warning
                }
                else {
                    $SortedData = $Data | Sort-Object -Property Domain, Severity
                    $OutputPath = Join-Path $ScriptDirectory "Output"
                    Export-AssessmentData -Data $SortedData -OutputPath $OutputPath -FilePrefix "DomainRisks"
                }
            }
            
            "2" {
                Show-EntityQueryMenu -BaseUrl $SelectedRegion.Url -AccessToken $AccessToken
            }
            
            "3" {
                Write-Log "Script execution Exited by user"
                exit 0
            }
            
            default {
                Write-Host "Invalid choice. Please try again." -ForegroundColor Yellow
            }
        }
    } while ($true)
}
catch {
    Write-Log "Script execution failed: $_" -Level Error
    exit 1
}