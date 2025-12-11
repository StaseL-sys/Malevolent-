# Malevolent Security Scanner

A comprehensive pentesting learning and security assessment platform for educational purposes. Learn to identify and fix security vulnerabilities across websites, applications, networks, cloud infrastructure, IoT devices, financial systems, and more.

**For Educational Purposes Only** - Designed to help aspiring cybersecurity professionals learn penetration testing, security assessment, and vulnerability remediation.

## Features

- **🔍 Security Scanner**: Assess security posture across 9 different asset types
  - **Website security**: HTTPS, headers, cookies, XSS, CSRF, SQL injection
  - **Email security**: SPF, DKIM, DMARC, relay protection
  - **Server security**: Firewall, ports, SSH, patches, backups
  - **Application security**: Secrets, dependencies, authentication, rate limiting
  - **Data security**: Encryption, access control, backups, password hashing
  - **Finance security**: PCI DSS, payment tokenization, transaction security, KYC/AML
  - **IoT security**: Firmware updates, default credentials, network isolation
  - **Network security**: WiFi, VPN, DNS, segmentation, MITM protection
  - **Cloud security**: IAM, misconfigurations, container security, serverless

- **📚 Knowledge Base**: Learn about 50+ vulnerabilities
  - Detailed vulnerability descriptions with severity ratings
  - Real-world impact analysis
  - Step-by-step remediation guides
  - External learning resources (OWASP, NIST, etc.)

- **📝 Interactive Checklists**: Self-assessment checklists for each security domain

- **🎓 Learning Modules**: 16 structured courses covering:
  - Web Security, API Security, Network Pentesting
  - Cloud Security, IoT Security, Cryptocurrency Security
  - Financial Systems, E-Commerce Security
  - Incident Response, Social Engineering
  - Compliance Frameworks (PCI DSS, GDPR, HIPAA, SOC 2)

## Target Audiences

- Aspiring cybersecurity professionals and pentesters
- Security students and educators
- Developers learning secure coding practices
- IT professionals improving infrastructure security
- Compliance officers understanding security requirements

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

1. **Choose a Target Type**: Select from 9 assessment types (Website, Email, Server, Application, Data, Finance, IoT, Network, or Cloud)

2. **Complete the Checklist**: Answer security configuration questions honestly for self-assessment

3. **Review Results**: Get a security grade (A-F) with detailed findings and severity ratings

4. **Learn to Fix**: Each finding includes step-by-step remediation guidance and resources

5. **Explore the Knowledge Base**: Browse 50+ vulnerabilities with detection methods and fixes

6. **Take Learning Modules**: Complete structured courses to master different security domains

## Security Domains Covered

### Website Security
- HTTPS/SSL configuration
- Security headers (CSP, HSTS, X-Frame-Options)
- Cookie security, XSS and CSRF protection
- SQL injection prevention

### Email Security  
- SPF, DKIM, DMARC configuration
- TLS encryption, Open relay prevention

### Server Security
- Firewall configuration, Port management
- SSH hardening, Patch management

### Application Security
- Secrets management, Dependency vulnerabilities
- Authentication, Authorization, Rate limiting

### Data Security
- Encryption at rest and in transit
- Password hashing, Access controls
- Data retention and minimization

### Finance Security (NEW)
- PCI DSS compliance, Payment tokenization
- Transaction security, KYC/AML controls
- Cryptocurrency wallet security
- API security for financial systems

### IoT Security (NEW)
- Firmware update security, Default credentials
- Physical access protection
- Smart home device privacy
- Network isolation

### Network Security (NEW)
- WiFi security (WPA3), Network segmentation
- VPN security, DNS security (DNSSEC)
- Man-in-the-middle attack prevention

### Cloud Security (NEW)
- Cloud resource misconfigurations
- IAM permissions and policies
- Container and serverless security
- Secret management in cloud

## Educational Disclaimer

**This tool is designed strictly for educational purposes** to help individuals learn cybersecurity concepts, penetration testing methodologies, and security assessment techniques. 

**Guidelines:**
- Use only on systems you own or have explicit permission to test
- Never use for unauthorized access or malicious purposes
- Respect privacy and data protection laws (GDPR, CCPA, etc.)
- Follow responsible disclosure practices
- Use knowledge to improve security, not exploit vulnerabilities

## Learning Modules

The platform includes 16 comprehensive learning modules:

**Beginner Level:**
- Web Security Basics
- Social Engineering & Phishing

**Intermediate Level:**
- Email Authentication
- Server Hardening
- Secure Coding Practices
- Wireless Security
- E-Commerce & Retail Security
- Compliance Frameworks

**Advanced Level:**
- Data Protection
- Financial Systems Security
- IoT Device Pentesting
- Network Penetration Testing
- Cloud Security & Pentesting
- API Security Testing
- Cryptocurrency & Blockchain Security
- Incident Response & Forensics

## Tech Stack

- React 19
- Vite 7
- Vitest for testing

## License

This project is licensed under the Mozilla Public License 2.0 - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool provides educational guidance based on self-reported information. For production systems, always consult with security professionals and perform comprehensive penetration testing.
