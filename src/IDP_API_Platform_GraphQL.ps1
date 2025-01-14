#!/usr/bin/env pwsh

<#
=============================================================================
 Script: IDP GraphQL API Platform
 Purpose: Performs IDP GraphQL Queries based on IDP API
 Author: K.G @ Hawk1811
 Creation Date: January 2025
 Last Modified: January 2025
=============================================================================

MIT License

Copyright (c) 2025 Your_Nickname

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
=============================================================================

.SYNOPSIS
    IDP GraphQL API Platform for performing various security assessments.

.DESCRIPTION
    This script provides functionality to interact with the IDP GraphQL API,
    including domain risk assessment, entity queries, and service access analysis.
    Supports both interactive and automated execution modes.

.NOTES
    Version: 1.0.0
    Author: K.G @ Hawk1811
    Requirements: PowerShell 5.1 or higher
#>


[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$API_ID,
    
    [Parameter(Mandatory=$false)]
    [string]$API_SECRET,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('US-1', 'US-2', 'EU-1', 'US-GOV-1')]
    [string]$REGION,

    # Query Type Selection
    [Parameter(Mandatory=$false)]
    [ValidateSet('DomainRisks', 'Entities', 'ServiceAccess')]
    [string]$QueryType,

    # Service Access Parameters
    [Parameter(Mandatory=$false)]
    [string[]]$Protocols,
    [Parameter(Mandatory=$false)]
    [string[]]$Services,
    [Parameter(Mandatory=$false)]
    [int]$FetchSize = 1000,

    # Domain Risks Parameters
    [Parameter(Mandatory=$false)]
    [string]$DomainName,
    [Parameter(Mandatory=$false)]
    [int]$RiskScore,

    # Entity Query Parameters
    [Parameter(Mandatory=$false)]
    [string]$EntityType,
    [Parameter(Mandatory=$false)]
    [string]$SearchQuery,

    # Scheduling Parameters
    [Parameter(Mandatory=$false)]
    [ValidatePattern('^(\d+[mhdw])?$')]
    [string]$Schedule,
    
    [Parameter(Mandatory=$false)]
    [int]$RunLimit = 0
)

Clear-Host

#-------------------------------------------------------------------------
# Get External IP Address
#-------------------------------------------------------------------------
function Get-ExternalIPAddress {
    $ipCheckUrls = @(
        'https://api.ipify.org',
        'https://checkip.amazonaws.com',
        'https://icanhazip.com'
    )
    
    foreach ($url in $ipCheckUrls) {
        try {
            $externalIP = Invoke-RestMethod -Uri $url -TimeoutSec 3
            Write-Log "Successfully retrieved external IP from $url"
            return $externalIP.Trim()
        }
        catch {
            Write-Log "Failed to fetch IP from $url : $_" -Level Warning
            continue
        }
    }
    
    Write-Log "Unable to fetch external IP from any source" -Level Warning
    return $null
}

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
# Constants
#-------------------------------------------------------------------------
$PROTOCOL_TYPES = @(
    'KERBEROS', 'LDAP', 'NTLM', 'DCE_RPC', 'SSL', 'UNKNOWN'
)

$SERVICE_TYPES = @(
    'LDAP', 'WEB', 'FILE_SHARE', 'DB', 'RPCSS', 'REMOTE_DESKTOP', 
    'SCCM', 'SIP', 'DNS', 'MAIL', 'NTLM', 'COMPUTER_ACCESS', 
    'GENERIC_CLOUD', 'SERVICE_ACCOUNT', 'UNKNOWN'
)

$DATA_FETCH_OPTIONS = @(
    1000, 5000, 10000, 50000, 100000
)

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
# Authentication
#-------------------------------------------------------------------------
function Get-CrowdStrikeToken {
    param (
        [string]$BaseUrl,
        [string]$ProvidedApiId,
        [string]$ProvidedApiSecret
    )
    
    try {
        if ([string]::IsNullOrEmpty($ProvidedApiId)) {
            $ApiClientId = Read-Host "Enter your API Client ID"
        } else {
            $ApiClientId = $ProvidedApiId
        }
        
        if ([string]::IsNullOrEmpty($ProvidedApiSecret)) {
            $ApiClientSecret = Read-Host "Enter your API Client Secret" -AsSecureString
            $ApiClientSecretPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiClientSecret)
            )
        } else {
            $ApiClientSecretPlainText = $ProvidedApiSecret
        }
        
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
# Service Access Query
#-------------------------------------------------------------------------
function Get-ServiceAccessData {
    param (
        [string]$BaseUrl,
        [string]$AccessToken,
        [string[]]$SelectedProtocols,
        [string[]]$SelectedServices,
        [string]$BeforeCursor = $null,
        [int]$PageSize = 1000
    )
    
    try {
        Write-Log "Executing service access query"
        
        $filterPart = "all: {"
        if ($SelectedProtocols.Count -gt 0) {
            $protocolsStr = $SelectedProtocols -join ', '
            $filterPart += " protocolTypes: [$protocolsStr]"
        }
        if ($SelectedServices.Count -gt 0) {
            if ($SelectedProtocols.Count -gt 0) { $filterPart += ',' }
            $servicesStr = $SelectedServices -join ', '
            $filterPart += " targetServiceTypes: [$servicesStr]"
        }
        $filterPart += " }"

        $GraphQLQuery = @"
{
    timeline(
        types: [SERVICE_ACCESS]
        activityQuery: { $filterPart }
        last: $PageSize
        $(if($BeforeCursor){"before: `"$BeforeCursor`""})
    ) {
        pageInfo {
            hasPreviousPage
            startCursor
        }
        nodes {
            timestamp
            eventType
            eventLabel
            ... on TimelineServiceAccessEvent {
                protocolType
                ipAddress
                userEntity {
                    primaryDisplayName
                    secondaryDisplayName
                }
                targetEndpointEntity {
                    hostName
                    lastIpAddress
                }
            }
        }
    }
}
"@
        
        $Response = Invoke-RestMethod -Method POST -Uri "$BaseUrl/identity-protection/combined/graphql/v1" `
            -Headers @{
                'Authorization' = "Bearer $AccessToken"
                'Content-Type' = 'application/json'
            } `
            -Body (@{ query = $GraphQLQuery } | ConvertTo-Json -Depth 10)

        $result = @{
            Data = $Response.data.timeline.nodes | ForEach-Object {
                [PSCustomObject]@{
                    Timestamp = [DateTime]$_.timestamp
                    IpAddress = $_.ipAddress
                    PrimaryDisplayName = $_.userEntity.primaryDisplayName
                    SecondaryDisplayName = $_.userEntity.secondaryDisplayName
                    HostName = $_.targetEndpointEntity.hostName
                    TargetIp = $_.targetEndpointEntity.lastIpAddress
                    EventLabel = $_.eventLabel
                    ProtocolType = $_.protocolType
                }
            }
            PageInfo = $Response.data.timeline.pageInfo
        }
        
        return $result
    }
    catch {
        Write-Log "Error executing service access query: $_" -Level Error
        throw
    }
}

#-------------------------------------------------------------------------
# Domain Risks Data
#-------------------------------------------------------------------------
function Get-DomainRisksData {
    param (
        [string]$BaseUrl,
        [string]$AccessToken,
        [string]$Domain,
        [int]$MinRiskScore = 0
    )
    
    try {
        Write-Log "Executing domain risks query for domain: $Domain"
        
        $GraphQLQuery = @"
{
    domainRisks(domain: "$Domain") {
        riskScore
        riskFactors {
            category
            description
            severity
        }
        domainInfo {
            registrar
            creation
            expiration
            lastUpdate
        }
    }
}
"@
        
        $Response = Invoke-RestMethod -Method POST -Uri "$BaseUrl/identity-protection/combined/graphql/v1" `
            -Headers @{
                'Authorization' = "Bearer $AccessToken"
                'Content-Type' = 'application/json'
            } `
            -Body (@{ query = $GraphQLQuery } | ConvertTo-Json)

        return $Response.data.domainRisks
    }
    catch {
        Write-Log "Error executing domain risks query: $_" -Level Error
        throw
    }
}

#-------------------------------------------------------------------------
# Entity Query
#-------------------------------------------------------------------------
function Get-EntityData {
    param (
        [string]$BaseUrl,
        [string]$AccessToken,
        [string]$Type,
        [string]$Query
    )
    
    try {
        Write-Log "Executing entity query of type $Type with query: $Query"
        
        $GraphQLQuery = @"
{
    entitySearch(type: $Type, query: "$Query") {
        nodes {
            id
            type
            primaryDisplayName
            secondaryDisplayName
            properties
        }
    }
}
"@
        
        $Response = Invoke-RestMethod -Method POST -Uri "$BaseUrl/identity-protection/combined/graphql/v1" `
            -Headers @{
                'Authorization' = "Bearer $AccessToken"
                'Content-Type' = 'application/json'
            } `
            -Body (@{ query = $GraphQLQuery } | ConvertTo-Json)

        return $Response.data.entitySearch.nodes
    }
    catch {
        Write-Log "Error executing entity query: $_" -Level Error
        throw
    }
}

#-------------------------------------------------------------------------
# Export Function
#-------------------------------------------------------------------------
function Export-AssessmentData {
    param (
        [Parameter(Mandatory=$true)]
        [object[]]$Data,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$true)]
        [string]$FilePrefix
    )
    
    try {
        if (-not (Test-Path -Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $OutputPath -ChildPath "${FilePrefix}_${timestamp}.csv"
        $jsonPath = Join-Path -Path $OutputPath -ChildPath "${FilePrefix}_${timestamp}.json"
        
        # Export to CSV
        $Data | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Log "Data exported to CSV: $csvPath"
        
        # Export to JSON
        $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath
        Write-Log "Data exported to JSON: $jsonPath"
    }
    catch {
        Write-Log "Error exporting data: $_" -Level Error
        throw
    }
}

#-------------------------------------------------------------------------
# Scheduling Functions
#-------------------------------------------------------------------------
function Convert-ScheduleToMinutes {
    param (
        [string]$Schedule
    )
    
    if ([string]::IsNullOrEmpty($Schedule)) {
        return 0
    }

    $value = [int]($Schedule -replace '[mhdw]','')
    $unit = $Schedule[-1]
    
    switch ($unit) {
        'm' { return $value }
        'h' { return $value * 60 }
        'd' { return $value * 1440 }
        'w' { return $value * 10080 }
        default { throw "Invalid schedule format" }
    }
}

function Validate-QueryParameters {
    # If no QueryType is specified, assume interactive mode
    if (-not $QueryType) {
        return $true
    }

    # Validate automated mode parameters
    switch ($QueryType) {
        'ServiceAccess' {
            if (-not $FetchSize) {
                Write-Log "FetchSize parameter is required for ServiceAccess query" -Level Error
                return $false
            }
        }
        'DomainRisks' {
            if (-not $DomainName) {
                Write-Log "DomainName parameter is required for DomainRisks query" -Level Error
                return $false
            }
        }
        'Entities' {
            if (-not $EntityType -or -not $SearchQuery) {
                Write-Log "EntityType and SearchQuery parameters are required for Entities query" -Level Error
                return $false
            }
        }
    }
    return $true
}

function Execute-ScheduledTask {
    param (
        [string]$BaseUrl,
        [string]$AccessToken
    )

    # Create Output directory if it doesn't exist
    $OutputPath = Join-Path $ScriptDirectory "Output"
    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    switch ($QueryType) {
        'ServiceAccess' {
            $results = Get-ServiceAccessData -BaseUrl $BaseUrl -AccessToken $AccessToken `
                -SelectedProtocols $Protocols -SelectedServices $Services `
                -PageSize $FetchSize
            if ($results.Data.Count -gt 0) {
                Export-AssessmentData -Data $results.Data -OutputPath $OutputPath -FilePrefix "ServiceAccess"
            }
        }
        'DomainRisks' {
            $results = Get-DomainRisksData -BaseUrl $BaseUrl -AccessToken $AccessToken `
                -Domain $DomainName -MinRiskScore $RiskScore
            if ($results) {
                Export-AssessmentData -Data $results -OutputPath $OutputPath -FilePrefix "DomainRisks"
            }
        }
        'Entities' {
            $results = Get-EntityData -BaseUrl $BaseUrl -AccessToken $AccessToken `
                -Type $EntityType -Query $SearchQuery
            if ($results) {
                Export-AssessmentData -Data $results -OutputPath $OutputPath -FilePrefix "Entities"
            }
        }
    }
}

#-------------------------------------------------------------------------
# Main Execution Block
#-------------------------------------------------------------------------
try {
    Write-Log "Script execution started"
    
    if (-not (Validate-QueryParameters)) {
        exit 1
    }

    $scheduleMinutes = Convert-ScheduleToMinutes -Schedule $Schedule
    $runCount = 0
    
    do {
        Write-Log "Starting execution run #$($runCount + 1)"
        
        # Get and display external IP
        $externalIP = Get-ExternalIPAddress
        if ($externalIP) {
            Write-Log "External IP Address: $externalIP"
        }
        
        $Regions = Initialize-CrowdStrikeRegions
        
        # Handle region selection - either from parameter or user input
        if ($REGION) {
            $regionMapping = @{
                'US-1' = '1'
                'US-2' = '2'
                'EU-1' = '3'
                'US-GOV-1' = '4'
            }
            
            $regionKey = $regionMapping[$REGION]
            $SelectedRegion = $Regions[$regionKey]
            Write-Log "Using region: $REGION"
        } else {
            $SelectedRegion = Get-UserRegionSelection -Regions $Regions
        }
        
        $AccessToken = Get-CrowdStrikeToken -BaseUrl $SelectedRegion.Url -ProvidedApiId $API_ID -ProvidedApiSecret $API_SECRET
        
        # Check if running in automated or interactive mode
        if ($QueryType) {
            # Automated mode with command line parameters
            Execute-ScheduledTask -BaseUrl $SelectedRegion.Url -AccessToken $AccessToken
        } else {
            # Interactive mode with menu
            do {
                Write-Host "`nSelect an option:" -ForegroundColor Cyan
                Write-Host "1. Domain Risks Assessment"
                Write-Host "2. Entities Query"
                Write-Host "3. Service Access Query"
                Write-Host "4. Exit"
                
                $choice = Read-Host "`nEnter your choice (1-4)"
                
                switch ($choice) {
                    "1" {
                        Show-DomainAssessmentMenu -BaseUrl $SelectedRegion.Url -AccessToken $AccessToken
                    }
                    "2" {
                        Show-EntityQueryMenu -BaseUrl $SelectedRegion.Url -AccessToken $AccessToken
                    }
                    "3" {
                        Show-ServiceAccessMenu -BaseUrl $SelectedRegion.Url -AccessToken $AccessToken
                    }
                    "4" {
                        Write-Log "Script execution ended by user"
                        exit 0
                    }
                    default {
                        Write-Host "Invalid choice. Please try again." -ForegroundColor Yellow
                    }
                }
            } while ($true)
        }
        
        $runCount++
        
        # Check if we've hit the run limit (only applies to automated mode)
        if ($RunLimit -gt 0 -and $runCount -ge $RunLimit) {
            Write-Log "Reached run limit of $RunLimit. Exiting."
            break
        }
        
        # If scheduled, wait for next run (only applies to automated mode)
        if ($scheduleMinutes -gt 0) {
            Write-Log "Waiting $scheduleMinutes minutes until next run..."
            Start-Sleep -Seconds ($scheduleMinutes * 60)
        } else {
            break
        }
        
    } while ($true)
    
    Write-Log "Script execution completed successfully"
    exit 0
}
catch {
    Write-Log "Script execution failed: $_" -Level Error
    exit 1
}