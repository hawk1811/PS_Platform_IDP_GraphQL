# IDP GraphQL API Platform

A PowerShell-based security assessment tool for interacting with the Identity Protection (IDP) GraphQL API. This tool provides functionalities for domain risk assessment, entity queries, and security evaluations.

## 🔑 Key Features

- Domain risk assessment and analysis
- Advanced entity querying with multiple filters
- Security assessment reporting
- Automated and interactive execution modes
- Secure credential handling
- Comprehensive logging
- CSV and JSON export capabilities

## 🌐 Available Regions

- `US-1`: United States Primary Region (api.crowdstrike.com)
- `US-2`: United States Secondary Region (api.us-2.crowdstrike.com)
- `EU-1`: European Union Region (api.eu-1.crowdstrike.com)
- `US-GOV-1`: United States Government Region (api.laggar.gcw.crowdstrike.com)

## 🔍 Protocol Types

Available protocols for filtering in ServiceAccess queries:

### Authentication Protocols
- `KERBEROS`: A robust authentication protocol that provides strong security through ticket-based authentication
  - Used for: Domain authentication, single sign-on
  - Common in: Windows domains, enterprise environments
  - Default ports: 88 (TCP/UDP)

- `NTLM`: Windows New Technology LAN Manager authentication protocol
  - Used for: Legacy Windows authentication
  - Common in: Older Windows environments
  - Security note: Consider using Kerberos instead where possible

- `LDAP`: Lightweight Directory Access Protocol
  - Used for: Directory service access
  - Common in: Active Directory queries, user/group management
  - Default ports: 389 (LDAP), 636 (LDAPS)

### Communication Protocols
- `DCE_RPC`: Distributed Computing Environment/Remote Procedure Calls
  - Used for: Inter-process communication
  - Common in: Windows services, network services
  - Security note: Monitor for unusual RPC activity

- `SSL`: Secure Sockets Layer protocol
  - Used for: Encrypted communications
  - Common in: Web services, secure communications
  - Security note: Prefer TLS 1.2 or higher

- `UNKNOWN`: Unidentified or custom protocols
  - Used for: Protocols not matching known signatures
  - Security note: Monitor closely for potential security risks

## 🔧 Service Types

Available service types for filtering in ServiceAccess queries:

### Authentication & Directory Services
- `LDAP`: Directory services for user and resource management
  - Use cases: User authentication, group policies, resource lookup
  - Common ports: 389, 636 (LDAPS)
  - Security considerations: Monitor for brute force attempts, unauthorized queries

- `NTLM`: NT LAN Manager authentication services
  - Use cases: Legacy Windows authentication
  - Security considerations: Monitor for pass-the-hash attacks
  - Best practice: Consider migrating to Kerberos

### Remote Access Services
- `REMOTE_DESKTOP`: Remote desktop protocol services
  - Use cases: Remote system access and management
  - Default port: 3389
  - Security considerations: Monitor for brute force attempts, unusual access patterns

- `COMPUTER_ACCESS`: General computer access services
  - Use cases: System-level access and management
  - Security considerations: Monitor for unauthorized access attempts

### File & Data Services
- `FILE_SHARE`: Network file sharing services
  - Use cases: Shared folders, network drives
  - Common protocols: SMB, NFS
  - Security considerations: Monitor for unusual file access patterns

- `DB`: Database services
  - Use cases: Data storage and retrieval
  - Common ports: Various (1433 for MSSQL, 3306 for MySQL)
  - Security considerations: Monitor for unauthorized queries, data exfiltration

### Network Services
- `DNS`: Domain Name System services
  - Use cases: Name resolution, service discovery
  - Default ports: 53 (TCP/UDP)
  - Security considerations: Monitor for DNS tunneling, unusual query patterns

- `RPCSS`: Remote Procedure Call System Service
  - Use cases: Inter-process communication
  - Security considerations: Monitor for unauthorized RPC calls

- `SIP`: Session Initiation Protocol
  - Use cases: VoIP, video conferencing
  - Default ports: 5060, 5061
  - Security considerations: Monitor for toll fraud, unauthorized calls

### Communication Services
- `MAIL`: Email and messaging services
  - Use cases: Email communication, message transfer
  - Common ports: 25 (SMTP), 143 (IMAP), 993 (IMAPS)
  - Security considerations: Monitor for phishing, spam, data exfiltration

- `WEB`: Web-based services
  - Use cases: HTTP/HTTPS services, web applications
  - Default ports: 80, 443
  - Security considerations: Monitor for web attacks, unusual traffic patterns

### Management & Cloud Services
- `SCCM`: System Center Configuration Manager
  - Use cases: System management, software deployment
  - Security considerations: Monitor for unauthorized management actions

- `GENERIC_CLOUD`: Cloud-based services
  - Use cases: Various cloud service interactions
  - Security considerations: Monitor for data exfiltration, unauthorized access

- `SERVICE_ACCOUNT`: Service account access
  - Use cases: Automated system operations
  - Security considerations: Monitor for privilege escalation, account misuse

### Other
- `UNKNOWN`: Unidentified or custom services
  - Use cases: Services not matching known signatures
  - Security considerations: Monitor closely for potential security risks

## 📋 Prerequisites

- PowerShell 5.1 or higher
- Valid API credentials (Client ID and Secret)
- Network access to the API endpoints

## 🔒 Security Features

- **Local Processing**: All data processing is performed locally on your machine
- **No External Data Transfer**: The script only communicates with the specified API endpoints
- **Secure Credential Handling**: 
  - API secrets are handled as secure strings
  - Credentials are cleared from memory after use
  - Option to input sensitive data securely at runtime
- **Detailed Logging**: All operations are logged for audit purposes

## 📁 Directory Structure

```
.
├── IDP_API_Platform_GraphQL.ps1     # Main script
├── Output/                          # Generated reports
│   ├── DomainRisks_*.csv
│   ├── DomainRisks_*.json
│   ├── EntityQuery_*.csv
│   └── EntityQuery_*.json
└── Logs/                           # Operation logs
    └── SecurityAssessment_*.log
```

## 💻 Usage

### Interactive Mode

Simply run the script without parameters:

```powershell
.\IDP_API_Platform_GraphQL.ps1
```

### Automated Mode

#### Command Line Parameters

- `-API_ID`: Your API Client ID
- `-API_SECRET`: Your API Client Secret (optional, will prompt if not provided)
- `-REGION`: Target region (US-1, US-2, EU-1, US-GOV-1)
- `-QueryType`: Type of query to perform (DomainRisks, Entities, ServiceAccess)
- `-Schedule`: Schedule interval (e.g., "5m", "3h", "2d", "1w")
- `-RunLimit`: Number of times to run (0 = unlimited)
- `-FetchSize`: Number of records to retrieve per query (1000-100000)
- `-Protocols`: Array of protocols to filter
- `-Services`: Array of services to filter
- `-DomainName`: Target domain for assessment
- `-RiskScore`: Minimum risk score threshold
- `-EntityType`: Type of entity to query
- `-SearchQuery`: Search terms for entity queries

#### Basic Automation Examples

1. Domain Risks Assessment:
```powershell
.\IDP_API_Platform_GraphQL.ps1 -API_ID "your_id" -API_SECRET "your_secret" -REGION "US-1" -QueryType DomainRisks
```

2. Entity Query (Find locked accounts):
```powershell
.\IDP_API_Platform_GraphQL.ps1 -API_ID "your_id" -API_SECRET "your_secret" -REGION "US-1" -QueryType Entities -EntityType "accountLocked"
```

#### Secure Secret Input
To avoid exposing the API secret in command line history:

```powershell
.\IDP_API_Platform_GraphQL.ps1 -API_ID "your_id" -REGION "US-1" -QueryType DomainRisks
```
The script will securely prompt for the API secret.

#### Scheduled Execution Examples

1. Run Domain Risks assessment every 3 hours:
```powershell
.\IDP_API_Platform_GraphQL.ps1 -API_ID "your_id" -API_SECRET "your_secret" -REGION "US-1" -QueryType DomainRisks -Schedule "3h"
```

2. Run Entity Query every day for 5 times:
```powershell
.\IDP_API_Platform_GraphQL.ps1 -API_ID "your_id" -API_SECRET "your_secret" -REGION "US-1" -QueryType Entities -EntityType "inactive" -Schedule "1d" -RunLimit 5
```

3. Run assessment every week indefinitely:
```powershell
.\IDP_API_Platform_GraphQL.ps1 -API_ID "your_id" -API_SECRET "your_secret" -REGION "US-1" -QueryType DomainRisks -Schedule "1w"
```

4. Service Access query with specific protocols and services:
```powershell
.\IDP_API_Platform_GraphQL.ps1 -API_ID "your_id" -API_SECRET "your_secret" -REGION "US-1" -QueryType ServiceAccess -Protocols @("KERBEROS","LDAP") -Services @("WEB","FILE_SHARE") -FetchSize 5000
```

5. Domain Risks assessment with minimum risk score:
```powershell
.\IDP_API_Platform_GraphQL.ps1 -API_ID "your_id" -API_SECRET "your_secret" -REGION "US-1" -QueryType DomainRisks -DomainName "example.com" -RiskScore 75
```

6. Complex entity query with scheduling:
```powershell
.\IDP_API_Platform_GraphQL.ps1 -API_ID "your_id" -API_SECRET "your_secret" -REGION "EU-1" -QueryType Entities -EntityType "hasVulnerableOs" -Schedule "12h" -RunLimit 10
```
```powershell
.\IDP_API_Platform_GraphQL.ps1 -API_ID "your_id" -API_SECRET "your_secret" -REGION "US-1" -QueryType DomainRisks -Schedule "1w"
```

## 🎯 Query Types

- `DomainRisks`: Assess security risks associated with domains
  - Parameters:
    - `DomainName`: Target domain for assessment
    - `RiskScore`: Minimum risk score threshold (0-100)

- `Entities`: Query for specific entity types with various filters
  - Parameters:
    - `EntityType`: Type of entity to query (see Entity Queries section)
    - `SearchQuery`: Specific search terms for the query

- `ServiceAccess`: Analyze service access patterns
  - Parameters:
    - `Protocols`: Array of protocol types to filter (see Protocol Types section)
    - `Services`: Array of service types to filter (see Service Types section)
    - `FetchSize`: Number of records to retrieve (1000-100000)

## ⏱️ Schedule Format Options
- Minutes: `"5m"`, `"30m"`, etc.
- Hours: `"1h"`, `"12h"`, etc.
- Days: `"1d"`, `"7d"`, etc.
- Weeks: `"1w"`, `"2w"`, etc.

## 📊 Available Entity Queries

1. Find locked accounts (`accountLocked`)
2. Find accounts with SSO enabled (`cloudEnabled`)
3. Find cloud-only accounts (`cloudOnly`)
4. Find accounts with old passwords (`hasAgedPassword`)
5. Find accounts with Falcon sensor (`hasAgent`)
6. Find accounts with exposed passwords (`hasExposedPassword`)
7. Find accounts with non-expiring passwords (`hasNeverExpiringPassword`)
8. Find accounts with open incidents (`hasOpenIncidents`)
9. Find endpoints with vulnerable OS (`hasVulnerableOs`)
10. Find accounts with weak passwords (`hasWeakPassword`)
11. Find inactive accounts (`inactive`)
12. Find learned entities (`learned`)
13. Find marked entities (`marked`)
14. Find shared accounts (`shared`)
15. Find stale accounts (`stale`)
16. Find unmanaged endpoints (`unmanaged`)
17. Find watched entities (`watched`)

## 📄 Output Files

The script generates two types of output files for each assessment:
- **CSV Files**: For easy import into spreadsheet applications
- **JSON Files**: For programmatic processing and data analysis

Files are saved in the `Output` directory with timestamps in their names.

## 📝 Logging

- All operations are logged to the `Logs` directory
- Log files include timestamps and severity levels (Info, Warning, Error)
- Each script execution creates a new log file

## ⚠️ Error Handling

The script includes comprehensive error handling:
- API communication errors
- Authentication failures
- Data processing issues
- Export operations
- All errors are logged with detailed information

## 🔐 Best Practices

1. **API Credentials**:
   - Store API credentials securely
   - Use the secure input option for the API secret
   - Rotate credentials regularly

2. **Network Security**:
   - Ensure secure network connection
   - Use appropriate proxy settings if required

3. **Data Handling**:
   - Regularly clean up old output files
   - Protect exported data appropriately
   - Review logs periodically

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

📝 Note: If you encounter PowerShell execution policy restrictions, you can run the script using:
powershell -ExecutionPolicy Bypass -File .\IDP_API_Platform_GraphQL.ps1

For permanent solution, run PowerShell as Administrator and execute:
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
