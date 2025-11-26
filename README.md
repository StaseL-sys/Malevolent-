# Malevolent Security Scanner

A comprehensive security learning and assessment platform that helps you find security leaks, breaches, and weaknesses in websites, applications, email systems, and data servers.

## Features

- **🔍 Security Scanner**: Assess security posture across different asset types
  - Website security (HTTPS, headers, cookies, XSS, CSRF)
  - Email security (SPF, DKIM, DMARC)
  - Server security (firewall, ports, SSH, patches)
  - Application security (secrets, dependencies, authentication)
  - Data security (encryption, access control, backups)

- **📚 Knowledge Base**: Learn about common vulnerabilities
  - Detailed vulnerability descriptions
  - Impact analysis
  - Step-by-step remediation guides
  - External learning resources

- **📝 Interactive Checklists**: Self-assessment checklists for each security domain

- **🎓 Learning Modules**: Structured courses to improve security knowledge

## Getting Started

### Prerequisites

- Node.js 18+ and npm

### Installation

```bash
cd security-scanner
npm install
```

### Development

```bash
npm run dev
```

Open http://localhost:5173 in your browser.

### Build for Production

```bash
npm run build
```

### Testing

```bash
npm run test
```

### Linting

```bash
npm run lint
```

## How to Use

1. **Choose a Target Type**: Select what you want to assess (Website, Email, Server, Application, or Data)

2. **Complete the Checklist**: Answer questions about your security configuration honestly

3. **Review Results**: Get a security grade with detailed findings

4. **Learn to Fix**: Each finding includes step-by-step remediation guidance

5. **Explore the Knowledge Base**: Browse the Learn section to understand vulnerabilities in depth

## Security Domains Covered

### Website Security
- HTTPS/SSL configuration
- Security headers (CSP, HSTS, X-Frame-Options)
- Cookie security
- Input validation
- XSS and CSRF protection

### Email Security  
- SPF records
- DKIM signing
- DMARC policies
- TLS encryption
- Open relay prevention

### Server Security
- Firewall configuration
- Port management
- SSH hardening
- Patch management
- Backup strategies

### Application Security
- Secrets management
- Dependency vulnerabilities
- Authentication best practices
- Rate limiting
- Secure logging

### Data Security
- Encryption at rest
- Encryption in transit
- Password hashing
- Access controls
- Data retention policies

## Tech Stack

- React 19
- Vite 7
- Vitest for testing

## License

This project is licensed under the Mozilla Public License 2.0 - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool provides educational guidance based on self-reported information. For production systems, always consult with security professionals and perform comprehensive penetration testing.
