# IDP GraphQL API Platform

A comprehensive PowerShell-based security assessment tool designed for interacting with the Identity Protection (IDP) GraphQL API. This platform facilitates domain risk assessment, entity queries, and service access analysis through both interactive and automated execution modes.

## Key Features

This platform provides a robust set of capabilities for security assessment and monitoring:

- Comprehensive domain risk assessment and analysis
- Detailed entity querying with multiple filter options
- Service access pattern analysis
- Flexible execution modes (interactive and automated)
- Secure credential management
- Detailed logging system
- Data export in both CSV and JSON formats

## Regional Support

The platform supports multiple operational regions:

- US-1: United States Primary Region (api.crowdstrike.com)
- US-2: United States Secondary Region (api.us-2.crowdstrike.com)
- EU-1: European Union Region (api.eu-1.crowdstrike.com)
- GOV-1: United States Government Region (api.laggar.gcw.crowdstrike.com)

## Prerequisites

To effectively use this platform, you need:

- PowerShell 5.1 or higher
- Valid API credentials (Client ID and Secret)
- Network access to the appropriate API endpoints

## Security Features

The platform implements several security measures:

- Local data processing with no external data transfers beyond API communication
- Secure credential handling with memory cleanup
- Option for runtime secure credential input
- Comprehensive audit logging
- Parameter validation and sanitization

## Directory Structure

The platform maintains the following directory structure:

```
.
├── IDP_API_Platform_GraphQL.ps1     # Main script
├── Output/                          # Assessment reports
│   ├── DomainRisks_*.csv
│   ├── DomainRisks_*.json
│   ├── EntityQuery_*.csv
│   ├── EntityQuery_*.json
│   ├── ServiceAccess_*.csv
│   └── ServiceAccess_*.json
└── Logs/                           # Operation logs
    └── SecurityAssessment_*.log
```

## Usage Instructions

### Interactive Mode

Launch the interactive mode by running the script without parameters:

```powershell
.\IDP_API_Platform_GraphQL.ps1
```

### Automated Mode

The platform supports various command-line parameters for automated execution:

```powershell
.\IDP_API_Platform_GraphQL.ps1 -API_ID <id> [-API_SECRET <secret>] -REGION <region> -QUERY <type> 
                              [-SCHEDULE <interval>] [-REPEAT <count>] [-PROTOCOL <protocols>] 
                              [-SERVICE <services>] [-DOMAINS <domains>]
```

Parameters:
- `-API_ID`: API Client ID for authentication
- `-API_SECRET`: API Client Secret (optional - will prompt if omitted)
- `-REGION`: Target region (US-1, US-2, EU-1, GOV-1)
- `-QUERY`: Query type (DomainAssessment, EntityQuery, ServiceAccess)
- `-SCHEDULE`: Schedule interval (e.g., 3m, 10h, 2d)
- `-REPEAT`: Execution repeat count
- `-PROTOCOL`: Protocol types for ServiceAccess
- `-SERVICE`: Service types for ServiceAccess
- `-DOMAINS`: Target domains for DomainAssessment

### Example Commands

Domain Assessment:
```powershell
.\IDP_API_Platform_GraphQL.ps1 -API_ID "your_id" -REGION "US-1" -QUERY "DomainAssessment" -DOMAINS "domain1.com","domain2.com"
```

Entity Query:
```powershell
.\IDP_API_Platform_GraphQL.ps1 -API_ID "your_id" -REGION "US-1" -QUERY "EntityQuery" "accountLocked"
```

Service Access Analysis:
```powershell
.\IDP_API_Platform_GraphQL.ps1 -API_ID "your_id" -REGION "US-1" -QUERY "ServiceAccess" -PROTOCOL "NTLM","KERBEROS" -SERVICE "WEB","FILE_SHARE"
```

Scheduled Execution:
```powershell
.\IDP_API_Platform_GraphQL.ps1 -API_ID "your_id" -REGION "US-1" -QUERY "DomainAssessment" -SCHEDULE "3h" -REPEAT 5
```

## Query Types and Options

### Protocol Types (for ServiceAccess)

Authentication Protocols:
- KERBEROS: Domain authentication and single sign-on (Port 88)
- NTLM: Legacy Windows authentication
- LDAP: Directory service access (Ports 389/636)

Communication Protocols:
- DCE_RPC: Inter-process communication
- SSL: Encrypted communications
- UNKNOWN: Unidentified protocols

### Service Types (for ServiceAccess)

Authentication & Directory:
- LDAP: Directory services (Ports 389/636)
- NTLM: Legacy Windows authentication

Remote Access:
- REMOTE_DESKTOP: Remote system access (Port 3389)
- COMPUTER_ACCESS: System-level access

File & Data:
- FILE_SHARE: Network file sharing
- DB: Database services

Network Services:
- DNS: Name resolution (Port 53)
- RPCSS: RPC System Service
- SIP: Session Initiation Protocol (Ports 5060/5061)

Communication:
- MAIL: Email services (Ports 25/143/993)
- WEB: Web services (Ports 80/443)

Management:
- SCCM: System Center Configuration Manager
- GENERIC_CLOUD: Cloud services
- SERVICE_ACCOUNT: Service account access
- UNKNOWN: Unidentified services

### Entity Query Types

The platform supports queries for various entity states:

1. accountLocked: Locked accounts
2. cloudEnabled: SSO-enabled accounts
3. cloudOnly: Cloud-only accounts
4. hasAgedPassword: Accounts with old passwords
5. hasAgent: Accounts with Falcon sensor
6. hasExposedPassword: Accounts with exposed passwords
7. hasNeverExpiringPassword: Non-expiring password accounts
8. hasOpenIncidents: Accounts with open incidents
9. hasVulnerableOs: Endpoints with vulnerable OS
10. hasWeakPassword: Weak password accounts
11. inactive: Inactive accounts
12. learned: Learned entities
13. marked: Marked entities
14. shared: Shared accounts
15. stale: Stale accounts
16. unmanaged: Unmanaged endpoints
17. watched: Watched entities

## Output and Logging

### Output Files
The platform generates two types of output files:
- CSV files for spreadsheet compatibility
- JSON files for programmatic analysis

Files are saved with timestamps in the Output directory.

### Logging System
- Operations are logged to the Logs directory
- Log files include timestamps and severity levels
- Each execution creates a new log file

## Best Practices

1. API Credential Management:
   - Store credentials securely
   - Use secure input for API secrets
   - Implement regular credential rotation

2. Network Security:
   - Ensure secure network connectivity
   - Configure appropriate proxy settings
   - Monitor API communication patterns

3. Data Management:
   - Implement regular output file cleanup
   - Secure exported data appropriately
   - Conduct periodic log reviews

## PowerShell Execution Policy

If you encounter execution policy restrictions, use:

```powershell
powershell -ExecutionPolicy Bypass -File .\IDP_API_Platform_GraphQL.ps1
```

For a permanent solution, run PowerShell as Administrator:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.
