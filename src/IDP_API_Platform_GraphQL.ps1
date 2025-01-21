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
    [string]$API_ID,
    [string]$API_SECRET,
    [ValidateSet('US-1', 'US-2', 'EU-1', 'GOV-1')]
    [string]$REGION,
    [ValidateSet('DomainAssessment', 'EntityQuery', 'ServiceAccess')]
    [string]$QUERY,
    [string]$SCHEDULE,
    [int]$REPEAT = 1,
    [string[]]$PROTOCOL,
    [string[]]$SERVICE,
    [string[]]$DOMAINS,
    [switch]$HELP
)

# Add custom parameter validation block at the beginning of the script
$ErrorActionPreference = 'Stop'

try {
    if ($QUERY -eq 'DomainAssessment' -and $args.Count -gt 0) {
        throw [System.Management.Automation.ValidationMetadataException]::new(
            "Invalid parameter usage. For DomainAssessment with multiple domains, use the -DOMAINS parameter.`n" +
            "Example: .\test.ps1 -API_ID 'xxx' -REGION 'US-1' -QUERY 'DomainAssessment' -DOMAINS 'domain1.com','domain2.com'`n" +
            "Note: Domains should be comma-separated and enclosed in quotes when using the -DOMAINS parameter."
        )
    }

    # Parameter validation
    $missingParams = @()
    if ($QUERY -and -not $API_ID) { $missingParams += "API_ID" }
    if ($PROTOCOL -and $QUERY -ne 'ServiceAccess') {
        throw [System.Management.Automation.ValidationMetadataException]::new(
            "Error: PROTOCOL parameter is only valid with ServiceAccess query type.`n" +
            "Example: .\test.ps1 -API_ID 'xxx' -REGION 'US-1' -QUERY 'ServiceAccess' -PROTOCOL 'NTLM','KERBEROS'"
        )
    }
    if ($SERVICE -and $QUERY -ne 'ServiceAccess') {
        throw [System.Management.Automation.ValidationMetadataException]::new(
            "Error: SERVICE parameter is only valid with ServiceAccess query type.`n" +
            "Example: .\test.ps1 -API_ID 'xxx' -REGION 'US-1' -QUERY 'ServiceAccess' -SERVICE 'WEB','FILE_SHARE'"
        )
    }
    if ($SCHEDULE -and -not $QUERY) {
        throw [System.Management.Automation.ValidationMetadataException]::new(
            "Error: SCHEDULE parameter requires a QUERY type.`n" +
            "Example: .\test.ps1 -API_ID 'xxx' -REGION 'US-1' -QUERY 'DomainAssessment' -SCHEDULE '1h'"
        )
    }
    if ($missingParams.Count -gt 0) {
        throw [System.Management.Automation.ValidationMetadataException]::new(
            "Error: The following required parameters are missing: $($missingParams -join ', ')`n" +
            "Please provide all required parameters to continue."
        )
    }
}
catch {
    Write-Log "Parameter validation error: $($_.Exception.Message)" -Level Error
    exit 1
}

#-------------------------------------------------------------------------
# Directory Setup
#-------------------------------------------------------------------------
# Get the directory where the script is located
$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $ScriptDirectory) {
    $ScriptDirectory = $PSScriptRoot
}
if (-not $ScriptDirectory) {
    $ScriptDirectory = (Get-Location).Path
}

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

#-------------------------------------------------------------------------
# Help Function
#-------------------------------------------------------------------------
function Show-Help {
    $helpText = @"
IDP GraphQL API Platform Script Help
===================================

USAGE:
    ./script.ps1 [-API_ID <id>] [-API_SECRET <secret>] [-REGION <region>] [-QUERY <query>] 
                 [-SCHEDULE <schedule>] [-REPEAT <count>] [-PROTOCOL <protocols>] 
                 [-SERVICE <services>] [-DOMAINS <domains>]

FLAGS:
    -API_ID        API Client ID for authentication
    -API_SECRET    API Client Secret for authentication (optional - will prompt if not provided)
    -REGION        Region selection (US-1, US-2, EU-1, GOV-1)
    -QUERY         Query type (DomainAssessment, EntityQuery, ServiceAccess)
    -SCHEDULE      Schedule interval (e.g., 3m, 10h, 2d)
    -REPEAT        Number of times to repeat scheduled execution
    -PROTOCOL      Protocol types for ServiceAccess (comma-separated list)
    -SERVICE       Service types for ServiceAccess (comma-separated list)
    -DOMAINS       Target domains for DomainAssessment (comma-separated list)
    -HELP          Display this help message

QUERY TYPES:
    DomainAssessment: Assess domain security
        Usage: -QUERY DomainAssessment -DOMAINS "domain1.com","domain2.com"
        Default: All domains if no domains specified in -DOMAINS parameter

    EntityQuery: Query specific entity types
        Usage: -QUERY EntityQuery <EventType>
        EventTypes: accountLocked, cloudEnabled, cloudOnly, hasAgedPassword,
                   hasAgent, hasExposedPassword, hasNeverExpiringPassword,
                   hasOpenIncidents, hasVulnerableOs, hasWeakPassword,
                   inactive, learned, marked, shared, stale, unmanaged, watched

    ServiceAccess: Query service access data
        Usage: -QUERY ServiceAccess [-PROTOCOL <types>] [-SERVICE <types>]
        Protocols: KERBEROS, LDAP, NTLM, DCE_RPC, SSL, UNKNOWN
        Services: LDAP, WEB, FILE_SHARE, DB, RPCSS, REMOTE_DESKTOP, SCCM,
                 SIP, DNS, MAIL, NTLM, COMPUTER_ACCESS, GENERIC_CLOUD,
                 SERVICE_ACCOUNT, UNKNOWN

EXAMPLES:
    # Run manual mode with pre-set credentials
    ./script.ps1 -API_ID "your_id" -REGION "US-1"

    # Run domain assessment for specific domains
    ./script.ps1 -API_ID "your_id" -API_SECRET "your_secret" -REGION "US-1" `
                -QUERY "DomainAssessment" -DOMAINS "domain1.com","domain2.com"

    # Run entity query for locked accounts
    ./script.ps1 -API_ID "your_id" -API_SECRET "your_secret" -REGION "US-1" `
                -QUERY "EntityQuery" "accountLocked"

    # Run service access query with specific protocols and services
    ./script.ps1 -API_ID "your_id" -API_SECRET "your_secret" -REGION "US-1" `
                -QUERY "ServiceAccess" -PROTOCOL "NTLM","KERBEROS" -SERVICE "WEB","FILE_SHARE"

    # Schedule execution every 3 hours, repeat 5 times
    ./script.ps1 -API_ID "your_id" -API_SECRET "your_secret" -REGION "US-1" `
                -QUERY "DomainAssessment" -DOMAINS "domain1.com" -SCHEDULE "3h" -REPEAT 5

NOTE: API_SECRET can be omitted from command line for security. If not provided,
      you will be prompted to enter it securely.
"@
    Write-Host $helpText
    exit 0
}

#-------------------------------------------------------------------------
# Clear Function
#-------------------------------------------------------------------------
function clearAll {	
    # Clear variables in all scopes
    Get-Variable -Scope Global | Where-Object { 
        $_.Options -notmatch "ReadOnly|Constant|AllScope" -and 
        $_.Name -notmatch "^(?:PWD|PSCommandPath|PSScriptRoot|MyInvocation)$"
    } | Remove-Variable -Force -ErrorAction SilentlyContinue

    # Clear specific scopes
    Get-Variable -Scope Script | Remove-Variable -Force -ErrorAction SilentlyContinue
    Get-Variable -Scope Local | Remove-Variable -Force -ErrorAction SilentlyContinue

    # Clear modules
    Remove-Module * -Force -ErrorAction SilentlyContinue

    # Clear error variable
    $error.Clear()

    # Force garbage collection
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    [System.GC]::Collect()
    Write-Log "Memory data was cleared" -Level info
}

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
# Schedule Parser
#-------------------------------------------------------------------------
function Parse-Schedule {
    param (
        [string]$Schedule
    )
    
    if (-not $Schedule) {
        return $null
    }
    
    $match = $Schedule -match '(\d+)([mhd])'
    if (-not $match) {
        Write-Log "Invalid schedule format. Use format: <number><unit> (e.g., 3m, 2h, 1d)" -Level Error
        exit 1
    }
    
    $value = [int]$matches[1]
    $unit = $matches[2]
    
    $minutes = switch ($unit) {
        'm' { $value }
        'h' { $value * 60 }
        'd' { $value * 1440 }
    }
    
    return $minutes
}

#-------------------------------------------------------------------------
# CrowdStrike Region Configuration
#-------------------------------------------------------------------------
function Initialize-CrowdStrikeRegions {
    return @{
        '1' = @{ Name = 'US-1'; Url = 'https://api.crowdstrike.com' }
        '2' = @{ Name = 'US-2'; Url = 'https://api.us-2.crowdstrike.com' }
        '3' = @{ Name = 'EU-1'; Url = 'https://api.eu-1.crowdstrike.com' }
        '4' = @{ Name = 'GOV-1'; Url = 'https://api.laggar.gcw.crowdstrike.com' }
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
        [string]$BaseUrl,
        [string]$ApiClientId,
        [string]$ApiClientSecret
    )
    
    try {
        if (-not $ApiClientId) {
            $ApiClientId = Read-Host "Enter your API Client ID"
        }
        
        if (-not $ApiClientSecret) {
            $ApiClientSecretSecure = Read-Host "Enter your API Client Secret" -AsSecureString
            $ApiClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiClientSecretSecure)
            )
        }
        
        Write-Log "Attempting to obtain OAuth2 token"
        $TokenResponse = Invoke-RestMethod -Method POST -Uri "$BaseUrl/oauth2/token" -Headers @{
            'Content-Type' = 'application/x-www-form-urlencoded'
        } -Body "client_id=$ApiClientId&client_secret=$ApiClientSecret"
        
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
        $ApiClientSecretSecure = $null
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
# Entity Query
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
# Service Access Query
#-------------------------------------------------------------------------
function Get-ServiceAccessData {
    param (
        [string]$BaseUrl,
        [string]$AccessToken,
        [string[]]$SelectedProtocols,
        [string[]]$SelectedServices,
        [string]$StartCursor = $null
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
        first: 1000
        sortOrder: DESCENDING
        $(if($StartCursor){"after: `"$StartCursor`""})
    ) {
        pageInfo {
            hasNextPage
            endCursor
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

        return @{
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
    }
    catch {
        Write-Log "Error executing service access query: $_" -Level Error
        throw
    }
}

#-------------------------------------------------------------------------
# Automated Execution Function
#-------------------------------------------------------------------------
function Start-AutomatedExecution {
    param (
        [string]$BaseUrl,
        [string]$AccessToken,
        [string]$Query,
        [string[]]$QueryParams,
        [string[]]$Protocols,
        [string[]]$Services,
        [string[]]$SpecificDomains
    )
    
    switch ($Query) {
        'DomainAssessment' {
            # Use specific domains if provided, otherwise get all domains
            $domains = if ($SpecificDomains) {
                Write-Log "Using specified domains: $($SpecificDomains -join ', ')"
                $SpecificDomains
            } else {
                Write-Log "No specific domains provided, fetching all domains"
                Get-DomainList -BaseUrl $BaseUrl -AccessToken $AccessToken
            }
            
            $Data = @()
            foreach ($Domain in $domains) {
                $Assessment = Get-SecurityAssessment -Domain $Domain -BaseUrl $BaseUrl -AccessToken $AccessToken
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
            
            if ($Data.Count -gt 0) {
                $OutputPath = Join-Path $ScriptDirectory "Output"
                Export-AssessmentData -Data $Data -OutputPath $OutputPath -FilePrefix "DomainRisks"
            }
        }
        
        'EntityQuery' {
            if (-not $QueryParams) {
                Write-Log "Entity type must be specified for EntityQuery" -Level Error
                exit 1
            }
            
            $validTypes = @('accountLocked', 'cloudEnabled', 'cloudOnly', 'hasAgedPassword',
                           'hasAgent', 'hasExposedPassword', 'hasNeverExpiringPassword',
                           'hasOpenIncidents', 'hasVulnerableOs', 'hasWeakPassword',
                           'inactive', 'learned', 'marked', 'shared', 'stale', 'unmanaged',
                           'watched')
            
            if ($validTypes -notcontains $QueryParams[0]) {
                Write-Log "Invalid entity type specified. Valid types: $($validTypes -join ', ')" -Level Error
                exit 1
            }
            
            $Data = @()
            $hasNextPage = $true
            $afterCursor = $null
            
            while ($hasNextPage) {
                $QueryParam = "$($QueryParams[0]):true"
                $Response = Get-EntityData -BaseUrl $BaseUrl -AccessToken $AccessToken -QueryParameter $QueryParam -AfterCursor $afterCursor
                
                if ($Response) {
                    $Data += $Response.nodes
                    $hasNextPage = $Response.pageInfo.hasNextPage
                    $afterCursor = $Response.pageInfo.endCursor
                }
                else {
                    $hasNextPage = $false
                }
                Start-Sleep -Milliseconds 100
            }
            
            if ($Data.Count -gt 0) {
                $OutputPath = Join-Path $ScriptDirectory "Output"
                Export-AssessmentData -Data $Data -OutputPath $OutputPath -FilePrefix "EntityQuery_$($QueryParams[0])"
            }
        }
        
        'ServiceAccess' {
            $selectedProtocols = if ($Protocols) { $Protocols } else { $PROTOCOL_TYPES }
            $selectedServices = if ($Services) { $Services } else { $SERVICE_TYPES }
            
            $allData = @()
            $hasNextPage = $true
            $endCursor = $null
            $totalRecords = 0
            
            while ($hasNextPage -and $totalRecords -lt 1000) {
                $results = Get-ServiceAccessData -BaseUrl $BaseUrl -AccessToken $AccessToken `
                    -SelectedProtocols $selectedProtocols -SelectedServices $selectedServices `
                    -StartCursor $endCursor
                
                if ($results.Data) {
                    $allData += $results.Data
                    $totalRecords = $allData.Count
                    $hasNextPage = $results.PageInfo.hasNextPage
                    $endCursor = $results.PageInfo.endCursor
                }
                else {
                    $hasNextPage = $false
                }
                Start-Sleep -Milliseconds 100
            }
            
            if ($allData.Count -gt 0) {
                $OutputPath = Join-Path $ScriptDirectory "Output"
                Export-AssessmentData -Data $allData -OutputPath $OutputPath -FilePrefix "ServiceAccess"
            }
        }
    }
}

#-------------------------------------------------------------------------
# Menu Functions
#-------------------------------------------------------------------------
function Show-ServiceAccessMenu {
    param (
        [string]$BaseUrl,
        [string]$AccessToken
    )
    
    Write-Host "`nService Access Query Configuration" -ForegroundColor Cyan
    
    # Protocol Selection
    Write-Host "`nStep 1: Select Protocol Types" -ForegroundColor Yellow
    Write-Host "Protocol Types (leave empty for all):"
    for ($i = 0; $i -lt $PROTOCOL_TYPES.Count; $i++) {
        Write-Host "$($i + 1). $($PROTOCOL_TYPES[$i])"
    }
    $protocolChoice = Read-Host "`nEnter protocol numbers (space-separated) or press Enter for all"
    
    # Service Type Selection
    Write-Host "`nStep 2: Select Service Types" -ForegroundColor Yellow
    Write-Host "Service Types (leave empty for all):"
    for ($i = 0; $i -lt $SERVICE_TYPES.Count; $i++) {
        Write-Host "$($i + 1). $($SERVICE_TYPES[$i])"
    }
    $serviceChoice = Read-Host "`nEnter service type numbers (space-separated) or press Enter for all"
    
    # Record Limit Selection
    Write-Host "`nStep 3: Select Number of Records to Fetch" -ForegroundColor Yellow
    Write-Host "1. 1,000 records"
    Write-Host "2. 5,000 records"
    Write-Host "3. 10,000 records"
    Write-Host "4. 50,000 records"
    Write-Host "5. 100,000 records"
    Write-Host "6. Custom number"
    
    $recordChoice = Read-Host "`nEnter your choice (1-6)"
    $recordLimit = switch ($recordChoice) {
        "1" { 1000 }
        "2" { 5000 }
        "3" { 10000 }
        "4" { 50000 }
        "5" { 100000 }
        "6" {
            $customLimit = Read-Host "Enter custom number (will be rounded to nearest 1000)"
            [math]::Ceiling([int]$customLimit / 1000) * 1000
        }
        default { 1000 } # Default to 1000 if invalid input
    }
    
    Write-Host "`nFetching $recordLimit records..." -ForegroundColor Cyan
    
    $selectedProtocols = @()
    if ($protocolChoice -ne '') {
        $selectedProtocols = $protocolChoice.Split(' ') | ForEach-Object {
            $index = [int]$_ - 1
            if ($index -ge 0 -and $index -lt $PROTOCOL_TYPES.Count) {
                $PROTOCOL_TYPES[$index]
            }
        }
    }
    
    $selectedServices = @()
    if ($serviceChoice -ne '') {
        $selectedServices = $serviceChoice.Split(' ') | ForEach-Object {
            $index = [int]$_ - 1
            if ($index -ge 0 -and $index -lt $SERVICE_TYPES.Count) {
                $SERVICE_TYPES[$index]
            }
        }
    }
    
    $allData = @()
    $hasNextPage = $true
    $endCursor = $null
    $totalRecords = 0
    $pageCount = 1

    Write-Host "`nFetching service access data..."
    while ($hasNextPage -and $totalRecords -lt $recordLimit) {
        Write-Host "Processing page $pageCount... ($totalRecords / $recordLimit records)"
        $results = Get-ServiceAccessData -BaseUrl $BaseUrl -AccessToken $AccessToken `
            -SelectedProtocols $selectedProtocols -SelectedServices $selectedServices `
            -StartCursor $endCursor

        if ($results.Data) {
            $allData += $results.Data
            $totalRecords = $allData.Count
            $hasNextPage = $results.PageInfo.hasNextPage
            $endCursor = $results.PageInfo.endCursor
            $pageCount++
        }
        else {
            $hasNextPage = $false
        }
        Start-Sleep -Milliseconds 100  # Rate limiting
    }

    Write-Host "Total records processed: $totalRecords"
    
    if ($allData.Count -gt 0) {
        $OutputPath = Join-Path $ScriptDirectory "Output"
        Export-AssessmentData -Data $allData -OutputPath $OutputPath -FilePrefix "ServiceAccess"
    }
    else {
        Write-Log "No service access data found for the selected criteria" -Level Warning
    }
}

function Show-DomainAssessmentMenu {
    param (
        [string]$BaseUrl,
        [string]$AccessToken
    )
    
    $domains = Get-DomainList -BaseUrl $BaseUrl -AccessToken $AccessToken
    
    Write-Host "`nAvailable Domains (leave empty for all):" -ForegroundColor Cyan
    for ($i = 0; $i -lt $domains.Count; $i++) {
        Write-Host "$($i + 1). $($domains[$i])"
    }
    
    $domainChoice = Read-Host "`nEnter domain numbers (space-separated) or press Enter for all"
    
    $selectedDomains = @()
    if ($domainChoice -eq '') {
        $selectedDomains = $domains
    }
    else {
        $selectedDomains = $domainChoice.Split(' ') | ForEach-Object {
            $index = [int]$_ - 1
            if ($index -ge 0 -and $index -lt $domains.Count) {
                $domains[$index]
            }
        }
    }
    
    $Data = @()
    foreach ($Domain in $selectedDomains) {
        $Assessment = Get-SecurityAssessment -Domain $Domain -BaseUrl $BaseUrl -AccessToken $AccessToken
        
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
    
    if ($Data.Count -gt 0) {
        $SortedData = $Data | Sort-Object -Property Domain, Severity
        $OutputPath = Join-Path $ScriptDirectory "Output"
        Export-AssessmentData -Data $SortedData -OutputPath $OutputPath -FilePrefix "DomainRisks"
    }
    else {
        Write-Log "No assessment data was collected" -Level Warning
    }
}

function Show-EntityQueryMenu {
    param (
        [string]$BaseUrl,
        [string]$AccessToken
    )
    
    $menuOptions = @{
        1 = @{ 'Parameter' = 'accountLocked'; 'Description' = 'Find locked accounts' }
        2 = @{ 'Parameter' = 'cloudEnabled'; 'Description' = 'Find accounts with SSO enabled' }
        3 = @{ 'Parameter' = 'cloudOnly'; 'Description' = 'Find cloud-only accounts' }
        4 = @{ 'Parameter' = 'hasAgedPassword'; 'Description' = 'Find accounts with old passwords' }
        5 = @{ 'Parameter' = 'hasAgent'; 'Description' = 'Find accounts with Falcon sensor' }
        6 = @{ 'Parameter' = 'hasExposedPassword'; 'Description' = 'Find accounts with exposed passwords' }
        7 = @{ 'Parameter' = 'hasNeverExpiringPassword'; 'Description' = 'Find accounts with non-expiring passwords' }
        8 = @{ 'Parameter' = 'hasOpenIncidents'; 'Description' = 'Find accounts with open incidents' }
        9 = @{ 'Parameter' = 'hasVulnerableOs'; 'Description' = 'Find endpoints with vulnerable OS' }
        10 = @{ 'Parameter' = 'hasWeakPassword'; 'Description' = 'Find accounts with weak passwords' }
        11 = @{ 'Parameter' = 'inactive'; 'Description' = 'Find inactive accounts' }
        12 = @{ 'Parameter' = 'learned'; 'Description' = 'Find learned entities' }
        13 = @{ 'Parameter' = 'marked'; 'Description' = 'Find marked entities' }
        14 = @{ 'Parameter' = 'shared'; 'Description' = 'Find shared accounts' }
        15 = @{ 'Parameter' = 'stale'; 'Description' = 'Find stale accounts' }
        16 = @{ 'Parameter' = 'unmanaged'; 'Description' = 'Find unmanaged endpoints' }
        17 = @{ 'Parameter' = 'watched'; 'Description' = 'Find watched entities' }
    }
    
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
            Write-Host "Processing page $pageCount"
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
}

#-------------------------------------------------------------------------
# Export Function
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
# Fetching External IPv4
#-------------------------------------------------------------------------
function Get-ExternalIPv4 {
    try {
        $ipv4Regex = '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        $externalIP = (Invoke-WebRequest -Uri 'https://api4.ipify.org' -TimeoutSec 5 -UseBasicParsing).Content.Trim()
        
        if ([string]::IsNullOrWhiteSpace($externalIP) -or $externalIP -notmatch $ipv4Regex) {
            throw "Invalid IPv4 response"
        }
        return $externalIP
    }
    catch {
        return "Failed to fetch External IP"
    }
}

#-------------------------------------------------------------------------
# Main Execution Block
#-------------------------------------------------------------------------
ClearAll
Clear-Host

try {
    Write-Log "Script execution started"
    $ipv4 = Get-ExternalIPv4
    Write-Log "Trying to fetch HOst External IP (For API access List): < $ipv4 >"
    
    if ($HELP) {
        Show-Help
    }
    
    $Regions = Initialize-CrowdStrikeRegions
    $regionMap = @{
        'US-1' = '1'
        'US-2' = '2'
        'EU-1' = '3'
        'GOV-1' = '4'
    }
    
    # Handle Region Selection with validation
    if ($REGION) {
        if (-not $regionMap.ContainsKey($REGION)) {
            Write-Log "Invalid region specified: $REGION" -Level Error
            Write-Host "Valid regions are: $($regionMap.Keys -join ', ')" -ForegroundColor Red
            exit 1
        }
        $regionChoice = $regionMap[$REGION]
        $SelectedRegion = $Regions[$regionChoice]
    }
    else {
        $SelectedRegion = Get-UserRegionSelection -Regions $Regions
    }
    
    # Handle Authentication with better error handling
    if ($API_ID) {
        if (-not $API_SECRET) {
            try {
                $secureSecret = Read-Host "Enter your API Client Secret" -AsSecureString
                $API_SECRET = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSecret)
                )
                if ([string]::IsNullOrWhiteSpace($API_SECRET)) {
                    throw "API Secret cannot be empty"
                }
            }
            catch {
                Write-Log "Failed to securely read API Secret: $_" -Level Error
                exit 1
            }
        }
        $AccessToken = Get-CrowdStrikeToken -BaseUrl $SelectedRegion.Url -ApiClientId $API_ID -ApiClientSecret $API_SECRET
    }
    else {
        $AccessToken = Get-CrowdStrikeToken -BaseUrl $SelectedRegion.Url
    }
    
    # Handle Automated or Manual Execution with improved scheduling
    if ($QUERY) {
        $scheduleMinutes = if ($SCHEDULE) { Parse-Schedule -Schedule $SCHEDULE } else { 0 }
        
        for ($i = 1; $i -le $REPEAT; $i++) {
            Write-Log "Execution $i of $REPEAT"
            Start-AutomatedExecution -BaseUrl $SelectedRegion.Url -AccessToken $AccessToken `
                -Query $QUERY -QueryParams $args -Protocols $PROTOCOL -Services $SERVICE `
                -SpecificDomains $DOMAINS
            
            if ($i -lt $REPEAT -and $scheduleMinutes -gt 0) {
                Write-Log "Waiting $scheduleMinutes minutes until next execution..."
                Start-Sleep -Seconds ($scheduleMinutes * 60)
            }
        }
    }
    else {
        # Manual menu-driven execution remains the same...
        do {
            Write-Host "`nSelect an option:" -ForegroundColor Cyan
            Write-Host "1. Domain Risks Assessment"
            Write-Host "2. Entities Query"
            Write-Host "3. Service Access Query"
            Write-Host "4. Exit"
            
            $choice = Read-Host "`nEnter your choice (1-4)"
            
            switch ($choice) {
                "1" { Show-DomainAssessmentMenu -BaseUrl $SelectedRegion.Url -AccessToken $AccessToken }
                "2" { Show-EntityQueryMenu -BaseUrl $SelectedRegion.Url -AccessToken $AccessToken }
                "3" { Show-ServiceAccessMenu -BaseUrl $SelectedRegion.Url -AccessToken $AccessToken }
                "4" { 
                    Write-Log "Script execution Exited by user"
                    clearAll
                    exit 0 
                }
                default { 
                    Write-Host "Invalid choice. Please select a number between 1 and 4." -ForegroundColor Yellow 
                }
            }
        } while ($true)
    }
}
catch {
    Write-Log "Script execution failed: $_" -Level Error
    clearAll
    exit 1
}
