/**
 * Security Knowledge Base
 * Contains vulnerability definitions, detection patterns, and remediation guides
 */

export const vulnerabilityCategories = {
  WEBSITE: 'website',
  EMAIL: 'email',
  SERVER: 'server',
  APPLICATION: 'application',
  DATA: 'data',
  FINANCE: 'finance',
  IOT: 'iot',
  NETWORK: 'network',
  CLOUD: 'cloud',
  THREATS: 'threats'
};

export const severityLevels = {
  CRITICAL: { name: 'Critical', color: '#dc2626', score: 10 },
  HIGH: { name: 'High', color: '#ea580c', score: 8 },
  MEDIUM: { name: 'Medium', color: '#ca8a04', score: 5 },
  LOW: { name: 'Low', color: '#16a34a', score: 2 },
  INFO: { name: 'Informational', color: '#2563eb', score: 1 }
};

export const vulnerabilityDatabase = {
  // Website Security Issues
  website: [
    {
      id: 'missing-https',
      name: 'Missing HTTPS/SSL Certificate',
      category: 'website',
      severity: 'CRITICAL',
      description: 'The website does not use HTTPS encryption, exposing user data to interception.',
      impact: 'Attackers can intercept sensitive data like passwords, credit cards, and personal information through man-in-the-middle attacks.',
      detection: 'Check if URL begins with http:// instead of https://',
      howToFix: [
        'Obtain an SSL/TLS certificate (free options: Let\'s Encrypt, Cloudflare)',
        'Install the certificate on your web server',
        'Configure your web server to redirect HTTP to HTTPS',
        'Update all internal links to use HTTPS',
        'Enable HSTS (HTTP Strict Transport Security)'
      ],
      resources: [
        { title: 'Let\'s Encrypt - Free SSL Certificates', url: 'https://letsencrypt.org' },
        { title: 'Mozilla SSL Configuration Generator', url: 'https://ssl-config.mozilla.org' }
      ]
    },
    {
      id: 'missing-security-headers',
      name: 'Missing Security Headers',
      category: 'website',
      severity: 'HIGH',
      description: 'Important HTTP security headers are not configured.',
      impact: 'Without security headers, the website is vulnerable to XSS attacks, clickjacking, MIME sniffing, and other browser-based attacks.',
      detection: 'Check HTTP response headers for: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, X-XSS-Protection',
      howToFix: [
        'Add Content-Security-Policy header to prevent XSS attacks',
        'Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking',
        'Add X-Content-Type-Options: nosniff to prevent MIME type sniffing',
        'Add Strict-Transport-Security header to enforce HTTPS',
        'Add Referrer-Policy to control referrer information'
      ],
      resources: [
        { title: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers' },
        { title: 'Security Headers Scanner', url: 'https://securityheaders.com' }
      ]
    },
    {
      id: 'outdated-software',
      name: 'Outdated Server Software',
      category: 'website',
      severity: 'HIGH',
      description: 'Web server or CMS software is outdated and may contain known vulnerabilities.',
      impact: 'Outdated software often contains publicly known vulnerabilities that attackers can easily exploit.',
      detection: 'Check Server header, X-Powered-By header, or CMS version information',
      howToFix: [
        'Update your web server software to the latest stable version',
        'Keep your CMS (WordPress, Drupal, etc.) updated',
        'Enable automatic security updates when possible',
        'Remove version information from HTTP headers',
        'Set up vulnerability monitoring for your software stack'
      ],
      resources: [
        { title: 'CVE Details - Vulnerability Database', url: 'https://www.cvedetails.com' },
        { title: 'NIST National Vulnerability Database', url: 'https://nvd.nist.gov' }
      ]
    },
    {
      id: 'sql-injection',
      name: 'SQL Injection Vulnerability',
      category: 'website',
      severity: 'CRITICAL',
      description: 'The application may be vulnerable to SQL injection attacks.',
      impact: 'Attackers can read, modify, or delete database contents, potentially gaining access to all user data and credentials.',
      detection: 'Test input fields with SQL special characters and observe error messages',
      howToFix: [
        'Use parameterized queries (prepared statements)',
        'Implement input validation and sanitization',
        'Use ORM frameworks that handle SQL safely',
        'Apply principle of least privilege to database accounts',
        'Implement Web Application Firewall (WAF)'
      ],
      resources: [
        { title: 'OWASP SQL Injection Prevention', url: 'https://owasp.org/www-community/attacks/SQL_Injection' },
        { title: 'SQL Injection Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html' }
      ]
    },
    {
      id: 'xss-vulnerability',
      name: 'Cross-Site Scripting (XSS)',
      category: 'website',
      severity: 'HIGH',
      description: 'The website may be vulnerable to cross-site scripting attacks.',
      impact: 'Attackers can inject malicious scripts to steal cookies, session tokens, and perform actions on behalf of users.',
      detection: 'Test input fields with script tags and JavaScript payloads',
      howToFix: [
        'Encode all user-supplied output',
        'Implement Content Security Policy (CSP)',
        'Use modern frameworks with automatic XSS protection',
        'Validate and sanitize all user inputs',
        'Use HTTPOnly and Secure flags on cookies'
      ],
      resources: [
        { title: 'OWASP XSS Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html' }
      ]
    },
    {
      id: 'csrf-vulnerability',
      name: 'Cross-Site Request Forgery (CSRF)',
      category: 'website',
      severity: 'MEDIUM',
      description: 'Forms and state-changing requests lack CSRF protection.',
      impact: 'Attackers can trick users into performing unintended actions on websites where they are authenticated.',
      detection: 'Check for CSRF tokens in forms and verify SameSite cookie attributes',
      howToFix: [
        'Implement CSRF tokens on all state-changing forms',
        'Use SameSite cookie attribute (Strict or Lax)',
        'Verify the Origin and Referer headers',
        'Require re-authentication for sensitive actions',
        'Use modern frameworks with built-in CSRF protection'
      ],
      resources: [
        { title: 'OWASP CSRF Prevention', url: 'https://owasp.org/www-community/attacks/csrf' }
      ]
    },
    {
      id: 'insecure-cookies',
      name: 'Insecure Cookie Configuration',
      category: 'website',
      severity: 'MEDIUM',
      description: 'Cookies are not properly secured with appropriate flags.',
      impact: 'Session cookies can be intercepted or accessed by malicious scripts, leading to session hijacking.',
      detection: 'Inspect cookie attributes for Secure, HttpOnly, and SameSite flags',
      howToFix: [
        'Set the Secure flag on all cookies to require HTTPS',
        'Set the HttpOnly flag to prevent JavaScript access',
        'Configure appropriate SameSite attribute',
        'Set reasonable expiration times for session cookies',
        'Implement proper session management'
      ],
      resources: [
        { title: 'OWASP Session Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html' }
      ]
    }
  ],

  // Email Security Issues
  email: [
    {
      id: 'missing-spf',
      name: 'Missing SPF Record',
      category: 'email',
      severity: 'HIGH',
      description: 'The domain lacks an SPF (Sender Policy Framework) record.',
      impact: 'Without SPF, attackers can easily spoof emails from your domain, leading to phishing attacks targeting your contacts.',
      detection: 'Check DNS TXT records for SPF configuration',
      howToFix: [
        'Create an SPF TXT record in your DNS',
        'List all authorized mail servers in the SPF record',
        'Use -all (hard fail) for strict enforcement',
        'Keep SPF record under the 10 DNS lookup limit',
        'Test your SPF record after implementation'
      ],
      resources: [
        { title: 'SPF Record Syntax', url: 'https://www.spf-record.com' },
        { title: 'MXToolbox SPF Checker', url: 'https://mxtoolbox.com/spf.aspx' }
      ]
    },
    {
      id: 'missing-dkim',
      name: 'Missing DKIM Records',
      category: 'email',
      severity: 'HIGH',
      description: 'The domain lacks DKIM (DomainKeys Identified Mail) configuration.',
      impact: 'Without DKIM, email recipients cannot verify that emails from your domain have not been tampered with.',
      detection: 'Check DNS for DKIM selector records',
      howToFix: [
        'Generate a DKIM key pair (public and private)',
        'Add the public key as a DNS TXT record',
        'Configure your mail server to sign outgoing emails',
        'Use a key size of at least 2048 bits',
        'Rotate DKIM keys periodically'
      ],
      resources: [
        { title: 'DKIM.org', url: 'https://dkim.org' },
        { title: 'DKIM Key Checker', url: 'https://mxtoolbox.com/dkim.aspx' }
      ]
    },
    {
      id: 'missing-dmarc',
      name: 'Missing DMARC Policy',
      category: 'email',
      severity: 'HIGH',
      description: 'The domain lacks a DMARC (Domain-based Message Authentication) policy.',
      impact: 'Without DMARC, you have no control over how receiving servers handle emails that fail SPF/DKIM checks.',
      detection: 'Check DNS for _dmarc TXT record',
      howToFix: [
        'Create a _dmarc TXT record in your DNS',
        'Start with p=none to monitor without blocking',
        'Configure RUA/RUF for aggregate/forensic reports',
        'Gradually increase policy to quarantine or reject',
        'Monitor DMARC reports to identify issues'
      ],
      resources: [
        { title: 'DMARC.org', url: 'https://dmarc.org' },
        { title: 'DMARC Analyzer', url: 'https://mxtoolbox.com/dmarc.aspx' }
      ]
    },
    {
      id: 'open-relay',
      name: 'Open Email Relay',
      category: 'email',
      severity: 'CRITICAL',
      description: 'The mail server is configured as an open relay, accepting mail from any sender to any recipient.',
      impact: 'Spammers can use your server to send spam, causing your IP to be blacklisted and damaging your reputation.',
      detection: 'Test if the server accepts mail from external domains to external domains',
      howToFix: [
        'Configure your mail server to only accept relay from authenticated users',
        'Restrict relay to known IP addresses',
        'Implement SMTP authentication for outbound mail',
        'Regularly test your server for open relay vulnerabilities',
        'Monitor outbound email patterns for abuse'
      ],
      resources: [
        { title: 'MXToolbox Open Relay Test', url: 'https://mxtoolbox.com/diagnostic.aspx' }
      ]
    },
    {
      id: 'weak-tls',
      name: 'Weak Email TLS Configuration',
      category: 'email',
      severity: 'MEDIUM',
      description: 'The mail server uses weak or no TLS encryption.',
      impact: 'Email communications can be intercepted and read by attackers.',
      detection: 'Check mail server TLS configuration and supported cipher suites',
      howToFix: [
        'Enable TLS 1.2 or higher on your mail server',
        'Disable SSLv3, TLS 1.0, and TLS 1.1',
        'Use strong cipher suites',
        'Implement STARTTLS for encrypted connections',
        'Consider implementing MTA-STS for enforced encryption'
      ],
      resources: [
        { title: 'SSL Labs SMTP Test', url: 'https://www.ssllabs.com' }
      ]
    }
  ],

  // Server/Infrastructure Security Issues
  server: [
    {
      id: 'open-ports',
      name: 'Unnecessary Open Ports',
      category: 'server',
      severity: 'HIGH',
      description: 'The server has ports open that are not needed for its function.',
      impact: 'Each open port is a potential attack vector. Unnecessary services increase the attack surface.',
      detection: 'Perform port scanning to identify open ports',
      howToFix: [
        'Audit all running services and their required ports',
        'Disable or remove unnecessary services',
        'Configure firewall to block unused ports',
        'Use iptables, ufw, or cloud security groups',
        'Implement network segmentation'
      ],
      resources: [
        { title: 'Nmap Port Scanner', url: 'https://nmap.org' },
        { title: 'SANS Firewall Best Practices', url: 'https://www.sans.org/reading-room' }
      ]
    },
    {
      id: 'default-credentials',
      name: 'Default Credentials',
      category: 'server',
      severity: 'CRITICAL',
      description: 'Services or applications are using default usernames and passwords.',
      impact: 'Attackers can easily gain access using widely-known default credentials.',
      detection: 'Attempt to log in with common default credentials',
      howToFix: [
        'Change all default passwords immediately after installation',
        'Use strong, unique passwords for each service',
        'Implement password policies (length, complexity, rotation)',
        'Use a password manager for credential management',
        'Disable default accounts where possible'
      ],
      resources: [
        { title: 'Default Password List', url: 'https://cirt.net/passwords' }
      ]
    },
    {
      id: 'ssh-root-login',
      name: 'SSH Root Login Enabled',
      category: 'server',
      severity: 'HIGH',
      description: 'The server allows direct SSH login as root.',
      impact: 'If compromised, attackers immediately have full system access.',
      detection: 'Check SSH configuration for PermitRootLogin setting',
      howToFix: [
        'Set PermitRootLogin to no in sshd_config',
        'Create a regular user account for SSH access',
        'Use sudo for privileged operations',
        'Implement SSH key authentication',
        'Consider using SSH jump hosts/bastion hosts'
      ],
      resources: [
        { title: 'SSH Security Best Practices', url: 'https://www.ssh.com/academy/ssh/security' }
      ]
    },
    {
      id: 'unpatched-system',
      name: 'Unpatched Operating System',
      category: 'server',
      severity: 'CRITICAL',
      description: 'The operating system is missing security patches.',
      impact: 'Known vulnerabilities can be exploited by attackers using public exploits.',
      detection: 'Check for pending system updates',
      howToFix: [
        'Establish a regular patching schedule',
        'Enable automatic security updates',
        'Subscribe to security mailing lists for your OS',
        'Test patches in a staging environment first',
        'Maintain an inventory of all systems and their patch levels'
      ],
      resources: [
        { title: 'CVE Details', url: 'https://www.cvedetails.com' }
      ]
    },
    {
      id: 'weak-ssh-config',
      name: 'Weak SSH Configuration',
      category: 'server',
      severity: 'MEDIUM',
      description: 'SSH is configured with weak encryption or authentication methods.',
      impact: 'Attackers may be able to crack encryption or brute-force passwords.',
      detection: 'Audit SSH configuration and supported algorithms',
      howToFix: [
        'Disable password authentication, use keys only',
        'Use Ed25519 or RSA 4096-bit keys',
        'Disable weak cipher suites and MACs',
        'Implement fail2ban or similar for brute-force protection',
        'Change the default SSH port (security through obscurity)'
      ],
      resources: [
        { title: 'Mozilla SSH Guidelines', url: 'https://infosec.mozilla.org/guidelines/openssh' }
      ]
    },
    {
      id: 'missing-backup',
      name: 'Missing or Untested Backups',
      category: 'server',
      severity: 'HIGH',
      description: 'The system lacks proper backup procedures or backups have not been tested.',
      impact: 'Data loss from ransomware, hardware failure, or accidents may be unrecoverable.',
      detection: 'Review backup policies and test restoration procedures',
      howToFix: [
        'Implement the 3-2-1 backup rule',
        'Store backups in multiple locations including offsite',
        'Encrypt backup data',
        'Regularly test backup restoration',
        'Document backup and recovery procedures'
      ],
      resources: [
        { title: 'NIST Backup Guidelines', url: 'https://www.nist.gov/cyberframework' }
      ]
    }
  ],

  // Application Security Issues
  application: [
    {
      id: 'hardcoded-secrets',
      name: 'Hardcoded Secrets in Code',
      category: 'application',
      severity: 'CRITICAL',
      description: 'API keys, passwords, or other secrets are hardcoded in the application code.',
      impact: 'Secrets in code can be exposed through version control, logs, or decompilation.',
      detection: 'Search codebase for patterns matching API keys, passwords, tokens',
      howToFix: [
        'Move all secrets to environment variables',
        'Use a secrets management system (Vault, AWS Secrets Manager)',
        'Add secret files to .gitignore',
        'Implement secret rotation policies',
        'Use git-secrets or similar tools to prevent committing secrets'
      ],
      resources: [
        { title: 'OWASP Secrets Management', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html' },
        { title: 'GitGuardian', url: 'https://www.gitguardian.com' }
      ]
    },
    {
      id: 'insecure-dependencies',
      name: 'Vulnerable Dependencies',
      category: 'application',
      severity: 'HIGH',
      description: 'The application uses third-party libraries with known vulnerabilities.',
      impact: 'Attackers can exploit known vulnerabilities in outdated dependencies.',
      detection: 'Run dependency vulnerability scanners (npm audit, pip-audit, etc.)',
      howToFix: [
        'Regularly update all dependencies to latest versions',
        'Use automated dependency scanning in CI/CD',
        'Subscribe to security advisories for key dependencies',
        'Lock dependency versions and audit regularly',
        'Consider using Dependabot or Renovate for automated updates'
      ],
      resources: [
        { title: 'Snyk Vulnerability Database', url: 'https://snyk.io/vuln' },
        { title: 'npm Audit', url: 'https://docs.npmjs.com/cli/v8/commands/npm-audit' }
      ]
    },
    {
      id: 'insecure-deserialization',
      name: 'Insecure Deserialization',
      category: 'application',
      severity: 'CRITICAL',
      description: 'The application deserializes untrusted data without proper validation.',
      impact: 'Can lead to remote code execution, denial of service, or privilege escalation.',
      detection: 'Review code for deserialization of user-controlled data',
      howToFix: [
        'Avoid deserializing data from untrusted sources',
        'Use safe serialization formats like JSON instead of native formats',
        'Implement integrity checks on serialized objects',
        'Run deserialization code with minimal privileges',
        'Log and monitor deserialization errors'
      ],
      resources: [
        { title: 'OWASP Deserialization Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html' }
      ]
    },
    {
      id: 'broken-auth',
      name: 'Broken Authentication',
      category: 'application',
      severity: 'CRITICAL',
      description: 'Authentication mechanisms are improperly implemented.',
      impact: 'Attackers can compromise passwords, keys, or session tokens to assume other users\' identities.',
      detection: 'Test for weak passwords, session management issues, credential stuffing',
      howToFix: [
        'Implement multi-factor authentication (MFA)',
        'Use secure password hashing (bcrypt, Argon2)',
        'Implement account lockout after failed attempts',
        'Use secure session management',
        'Protect against credential stuffing with rate limiting'
      ],
      resources: [
        { title: 'OWASP Authentication Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html' }
      ]
    },
    {
      id: 'missing-rate-limiting',
      name: 'Missing Rate Limiting',
      category: 'application',
      severity: 'MEDIUM',
      description: 'APIs and endpoints lack rate limiting controls.',
      impact: 'Attackers can perform brute-force attacks, DDoS, or resource exhaustion.',
      detection: 'Test endpoints for response to rapid repeated requests',
      howToFix: [
        'Implement rate limiting on all public endpoints',
        'Use different limits for different endpoint sensitivities',
        'Implement progressive delays for repeated failures',
        'Use CAPTCHA for suspicious activity',
        'Monitor and alert on unusual traffic patterns'
      ],
      resources: [
        { title: 'OWASP Rate Limiting', url: 'https://owasp.org/www-community/controls/Rate_Limiting' }
      ]
    },
    {
      id: 'logging-sensitive-data',
      name: 'Logging Sensitive Data',
      category: 'application',
      severity: 'MEDIUM',
      description: 'Application logs contain sensitive information like passwords or tokens.',
      impact: 'Logs can be accessed by unauthorized parties, exposing sensitive data.',
      detection: 'Review application logs for sensitive data patterns',
      howToFix: [
        'Implement log filtering to remove sensitive data',
        'Never log passwords, tokens, or API keys',
        'Use structured logging with defined fields',
        'Encrypt logs at rest and in transit',
        'Implement proper log access controls'
      ],
      resources: [
        { title: 'OWASP Logging Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html' }
      ]
    }
  ],

  // Data Security Issues
  data: [
    {
      id: 'unencrypted-data',
      name: 'Unencrypted Sensitive Data',
      category: 'data',
      severity: 'CRITICAL',
      description: 'Sensitive data is stored without encryption.',
      impact: 'Data breaches will expose all sensitive information in plain text.',
      detection: 'Audit database and file storage for encryption status',
      howToFix: [
        'Implement encryption at rest for all sensitive data',
        'Use AES-256 or stronger encryption algorithms',
        'Properly manage encryption keys',
        'Consider database-level encryption',
        'Encrypt backups'
      ],
      resources: [
        { title: 'OWASP Cryptographic Storage Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html' }
      ]
    },
    {
      id: 'weak-password-storage',
      name: 'Weak Password Hashing',
      category: 'data',
      severity: 'CRITICAL',
      description: 'Passwords are stored with weak or no hashing.',
      impact: 'If the database is breached, all passwords can be easily recovered.',
      detection: 'Review password storage implementation in code',
      howToFix: [
        'Use bcrypt, Argon2, or PBKDF2 for password hashing',
        'Use a unique salt for each password',
        'Configure appropriate cost factors',
        'Never store passwords in plain text or with MD5/SHA1',
        'Implement password history to prevent reuse'
      ],
      resources: [
        { title: 'OWASP Password Storage Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html' }
      ]
    },
    {
      id: 'public-database',
      name: 'Publicly Accessible Database',
      category: 'data',
      severity: 'CRITICAL',
      description: 'Database ports are exposed to the public internet.',
      impact: 'Attackers can directly attack the database, potentially gaining full access to all data.',
      detection: 'Check if database ports (3306, 5432, 27017, etc.) are publicly accessible',
      howToFix: [
        'Place databases behind firewalls',
        'Only allow connections from application servers',
        'Use VPC or private networking',
        'Implement database authentication',
        'Enable SSL/TLS for database connections'
      ],
      resources: [
        { title: 'CIS Database Benchmarks', url: 'https://www.cisecurity.org/benchmark' }
      ]
    },
    {
      id: 'excessive-data-collection',
      name: 'Excessive Data Collection',
      category: 'data',
      severity: 'MEDIUM',
      description: 'The application collects more personal data than necessary.',
      impact: 'Increases privacy risk and regulatory exposure (GDPR, CCPA).',
      detection: 'Audit data collection practices against actual needs',
      howToFix: [
        'Implement data minimization - collect only what you need',
        'Create a data inventory documenting all personal data',
        'Define and enforce data retention policies',
        'Provide data deletion capabilities',
        'Implement privacy by design principles'
      ],
      resources: [
        { title: 'GDPR Data Minimization', url: 'https://gdpr.eu/article-5-how-to-process-personal-data' }
      ]
    },
    {
      id: 'missing-data-backup-encryption',
      name: 'Unencrypted Backups',
      category: 'data',
      severity: 'HIGH',
      description: 'Database or file backups are not encrypted.',
      impact: 'Stolen or lost backup media exposes all data.',
      detection: 'Review backup processes for encryption implementation',
      howToFix: [
        'Encrypt all backup files',
        'Use strong encryption keys',
        'Store encryption keys separately from backups',
        'Test backup restoration regularly',
        'Implement secure backup transfer protocols'
      ],
      resources: [
        { title: 'NIST Backup Encryption Guidelines', url: 'https://www.nist.gov/cyberframework' }
      ]
    }
  ],

  // Finance & Payment Security
  finance: [
    {
      id: 'payment-card-data-exposure',
      name: 'Payment Card Data Exposure',
      category: 'finance',
      severity: 'CRITICAL',
      description: 'Payment card data (PAN, CVV, expiry) is stored, transmitted, or logged insecurely.',
      impact: 'Breach of PCI DSS compliance, financial fraud, regulatory fines, loss of customer trust, potential card-not-present fraud.',
      detection: 'Audit database, logs, and code for unencrypted or unnecessarily stored card data',
      howToFix: [
        'Never store full PAN, CVV, or magnetic stripe data',
        'Use tokenization for card storage',
        'Implement PCI DSS compliant payment gateway',
        'Use end-to-end encryption for card data transmission',
        'Limit card data storage to tokenized references only',
        'Implement data masking (show only last 4 digits)',
        'Regular PCI DSS compliance audits'
      ],
      resources: [
        { title: 'PCI DSS Requirements', url: 'https://www.pcisecuritystandards.org' },
        { title: 'Payment Tokenization Guide', url: 'https://owasp.org/www-community/vulnerabilities/Payment_Card_Industry_Data_Security_Standard' }
      ]
    },
    {
      id: 'insecure-financial-api',
      name: 'Insecure Financial Transaction API',
      category: 'finance',
      severity: 'CRITICAL',
      description: 'Financial APIs lack proper authentication, rate limiting, or transaction validation.',
      impact: 'Unauthorized transfers, account takeover, financial loss, fraudulent transactions, API abuse.',
      detection: 'Test APIs for authentication bypass, replay attacks, and insufficient validation',
      howToFix: [
        'Implement OAuth 2.0 or strong API key authentication',
        'Use transaction signing with digital signatures',
        'Implement idempotency keys to prevent duplicate transactions',
        'Add strict rate limiting on financial operations',
        'Require multi-factor authentication for high-value transactions',
        'Implement real-time fraud detection',
        'Log all financial transactions with audit trails'
      ],
      resources: [
        { title: 'OWASP API Security Top 10', url: 'https://owasp.org/www-project-api-security' },
        { title: 'Financial API Security', url: 'https://www.openbanking.org.uk/security' }
      ]
    },
    {
      id: 'weak-transaction-integrity',
      name: 'Weak Transaction Integrity Checks',
      category: 'finance',
      severity: 'HIGH',
      description: 'Financial transactions lack integrity verification, allowing manipulation of amounts or recipients.',
      impact: 'Transaction tampering, incorrect payment amounts, fraudulent beneficiary changes, financial loss.',
      detection: 'Intercept and modify transaction parameters to test validation',
      howToFix: [
        'Implement cryptographic signing of transaction data',
        'Use HMAC or digital signatures to verify transaction integrity',
        'Validate all transaction parameters server-side',
        'Implement transaction confirmation workflow',
        'Use secure random transaction IDs',
        'Implement double-entry bookkeeping verification',
        'Add anomaly detection for unusual transaction patterns'
      ],
      resources: [
        { title: 'Transaction Security Best Practices', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html' }
      ]
    },
    {
      id: 'insufficient-kyc',
      name: 'Insufficient KYC/AML Controls',
      category: 'finance',
      severity: 'HIGH',
      description: 'Know Your Customer (KYC) and Anti-Money Laundering (AML) controls are weak or bypassable.',
      impact: 'Regulatory non-compliance, money laundering, terrorist financing, identity fraud, heavy fines.',
      detection: 'Review KYC verification process for weaknesses and bypass methods',
      howToFix: [
        'Implement multi-layered identity verification',
        'Use government ID verification services',
        'Implement liveness detection for document verification',
        'Monitor for suspicious transaction patterns',
        'Implement automated AML screening',
        'Maintain comprehensive audit logs',
        'Regular compliance training for staff'
      ],
      resources: [
        { title: 'FATF AML Guidelines', url: 'https://www.fatf-gafi.org' },
        { title: 'KYC Best Practices', url: 'https://www.swift.com/standards/kyc-registry' }
      ]
    },
    {
      id: 'cryptocurrency-wallet-security',
      name: 'Weak Cryptocurrency Wallet Security',
      category: 'finance',
      severity: 'CRITICAL',
      description: 'Cryptocurrency private keys or seed phrases are stored insecurely.',
      impact: 'Complete loss of funds, irreversible theft, no recourse for recovery.',
      detection: 'Audit storage mechanisms for private keys and wallet security',
      howToFix: [
        'Use hardware security modules (HSM) for key storage',
        'Implement multi-signature wallets for high-value accounts',
        'Use cold storage for majority of funds',
        'Encrypt private keys with strong passphrases',
        'Implement key sharding for critical wallets',
        'Regular security audits of wallet infrastructure',
        'Use time-locked transactions for added security'
      ],
      resources: [
        { title: 'Cryptocurrency Security Standards', url: 'https://www.ccss.info' },
        { title: 'Bitcoin Security Guide', url: 'https://bitcoin.org/en/secure-your-wallet' }
      ]
    },
    {
      id: 'price-manipulation',
      name: 'Price Oracle Manipulation',
      category: 'finance',
      severity: 'HIGH',
      description: 'Financial systems rely on single or easily manipulated price sources.',
      impact: 'Market manipulation, incorrect pricing, arbitrage exploitation, financial losses.',
      detection: 'Analyze price feed sources and test for manipulation scenarios',
      howToFix: [
        'Use multiple independent price oracles',
        'Implement price deviation checks and alerts',
        'Use time-weighted average prices (TWAP)',
        'Add circuit breakers for extreme price movements',
        'Verify oracle data cryptographically',
        'Implement fallback price sources',
        'Regular audits of price feed integrity'
      ],
      resources: [
        { title: 'Chainlink Oracle Security', url: 'https://docs.chain.link/docs/architecture-decentralized-model' }
      ]
    }
  ],

  // IoT & Hardware Security
  iot: [
    {
      id: 'default-iot-credentials',
      name: 'Default IoT Device Credentials',
      category: 'iot',
      severity: 'CRITICAL',
      description: 'IoT devices shipped with default usernames and passwords that are publicly known.',
      impact: 'Complete device compromise, botnet recruitment, privacy invasion, lateral network movement.',
      detection: 'Search device documentation and online databases for default credentials',
      howToFix: [
        'Force password change on first use',
        'Generate unique credentials per device',
        'Disable default accounts entirely',
        'Implement certificate-based authentication',
        'Regular firmware updates to patch vulnerabilities',
        'Network segmentation for IoT devices',
        'Monitor for unauthorized access attempts'
      ],
      resources: [
        { title: 'IoT Security Foundation', url: 'https://www.iotsecurityfoundation.org' },
        { title: 'NIST IoT Security Guidelines', url: 'https://www.nist.gov/programs-projects/nist-cybersecurity-iot-program' }
      ]
    },
    {
      id: 'insecure-firmware',
      name: 'Insecure Firmware Updates',
      category: 'iot',
      severity: 'CRITICAL',
      description: 'IoT firmware updates lack signature verification or use insecure channels.',
      impact: 'Malicious firmware injection, device bricking, backdoor installation, complete device control.',
      detection: 'Analyze firmware update process for security controls',
      howToFix: [
        'Implement code signing for all firmware',
        'Use secure boot to verify firmware integrity',
        'Encrypt firmware during transmission',
        'Implement rollback protection',
        'Use over-the-air (OTA) update security best practices',
        'Verify update server certificates',
        'Implement firmware version verification'
      ],
      resources: [
        { title: 'OWASP IoT Top 10', url: 'https://owasp.org/www-project-internet-of-things' },
        { title: 'IoT Firmware Security', url: 'https://www.embedded.com/firmware-security-best-practices' }
      ]
    },
    {
      id: 'physical-access-vulnerability',
      name: 'Physical Access Vulnerabilities',
      category: 'iot',
      severity: 'HIGH',
      description: 'Devices lack protection against physical tampering or debugging interfaces.',
      impact: 'Firmware extraction, key extraction, device cloning, reverse engineering.',
      detection: 'Physical inspection for exposed debug ports (JTAG, UART)',
      howToFix: [
        'Disable or remove debug interfaces in production',
        'Use tamper-evident seals and enclosures',
        'Implement secure boot and verified boot chains',
        'Use hardware security modules (HSM) for key storage',
        'Encrypt sensitive data in flash memory',
        'Add tamper detection circuitry',
        'Use chip-level security features (TrustZone, etc.)'
      ],
      resources: [
        { title: 'IoT Hardware Security Best Practices', url: 'https://www.owasp.org/index.php/IoT_Security_Guidance' }
      ]
    },
    {
      id: 'smart-home-privacy',
      name: 'Smart Home Device Privacy Leaks',
      category: 'iot',
      severity: 'HIGH',
      description: 'Smart home devices collect and transmit excessive personal data without proper consent.',
      impact: 'Privacy invasion, behavioral tracking, data sale to third parties, surveillance.',
      detection: 'Network traffic analysis to identify data being transmitted',
      howToFix: [
        'Implement data minimization - collect only necessary data',
        'Provide clear privacy policies and opt-in consent',
        'Encrypt all data transmission',
        'Implement local processing where possible',
        'Allow users to delete their data',
        'Regular privacy impact assessments',
        'Comply with GDPR, CCPA regulations'
      ],
      resources: [
        { title: 'IoT Privacy Guidelines', url: 'https://www.ftc.gov/tips-advice/business-center/guidance/internet-things-privacy-security-connected-world' }
      ]
    },
    {
      id: 'weak-iot-network-security',
      name: 'Weak IoT Network Security',
      category: 'iot',
      severity: 'HIGH',
      description: 'IoT devices use weak encryption or unencrypted communication protocols.',
      impact: 'Traffic interception, command injection, device control, network compromise.',
      detection: 'Packet capture and analysis of device communications',
      howToFix: [
        'Use TLS 1.3 for all network communications',
        'Implement certificate pinning',
        'Use VPN or encrypted tunnels for remote access',
        'Disable insecure protocols (Telnet, HTTP)',
        'Implement network segmentation',
        'Use strong WiFi encryption (WPA3)',
        'Regular security audits of network traffic'
      ],
      resources: [
        { title: 'IoT Network Security', url: 'https://www.cisco.com/c/en/us/solutions/internet-of-things/iot-security.html' }
      ]
    }
  ],

  // Network & Infrastructure Pentesting
  network: [
    {
      id: 'weak-wifi-security',
      name: 'Weak WiFi Security',
      category: 'network',
      severity: 'HIGH',
      description: 'Wireless networks use outdated encryption (WEP, WPA) or weak passwords.',
      impact: 'Unauthorized network access, traffic interception, man-in-the-middle attacks, rogue access points.',
      detection: 'WiFi scanning tools (airodump-ng, Kismet) to identify security protocols',
      howToFix: [
        'Use WPA3 encryption (or WPA2 as minimum)',
        'Implement strong, random WiFi passwords (20+ characters)',
        'Enable network isolation for guest networks',
        'Use enterprise WiFi with 802.1X authentication',
        'Disable WPS (WiFi Protected Setup)',
        'Hide SSID broadcast for corporate networks',
        'Regular wireless security audits'
      ],
      resources: [
        { title: 'WiFi Security Best Practices', url: 'https://www.wi-fi.org/discover-wi-fi/security' },
        { title: 'WPA3 Security', url: 'https://www.wi-fi.org/discover-wi-fi/wi-fi-certified-wpa3' }
      ]
    },
    {
      id: 'network-segmentation-failure',
      name: 'Poor Network Segmentation',
      category: 'network',
      severity: 'HIGH',
      description: 'Flat network architecture allows lateral movement between different security zones.',
      impact: 'Complete network compromise from single entry point, data breach expansion, difficulty in containment.',
      detection: 'Network mapping and penetration testing for lateral movement',
      howToFix: [
        'Implement VLANs to separate network segments',
        'Use internal firewalls between segments',
        'Apply zero-trust network principles',
        'Separate guest, corporate, and IoT networks',
        'Implement micro-segmentation for critical assets',
        'Use network access control (NAC)',
        'Regular network architecture reviews'
      ],
      resources: [
        { title: 'Network Segmentation Guide', url: 'https://www.nist.gov/publications/guide-securing-legacy-ieee-80211-wireless-networks' },
        { title: 'Zero Trust Architecture', url: 'https://www.nist.gov/publications/zero-trust-architecture' }
      ]
    },
    {
      id: 'dns-security-issues',
      name: 'DNS Security Vulnerabilities',
      category: 'network',
      severity: 'MEDIUM',
      description: 'DNS infrastructure lacks DNSSEC or is vulnerable to cache poisoning.',
      impact: 'Traffic redirection, phishing attacks, man-in-the-middle, DNS spoofing.',
      detection: 'DNS security audit tools (DNSViz, DNSSec-Analyzer)',
      howToFix: [
        'Implement DNSSEC for domain validation',
        'Use secure DNS resolvers (DNS-over-HTTPS, DNS-over-TLS)',
        'Enable DNS response rate limiting',
        'Separate authoritative and recursive DNS servers',
        'Implement DNS firewall/filtering',
        'Monitor for DNS anomalies',
        'Regular DNS security audits'
      ],
      resources: [
        { title: 'DNSSEC Deployment', url: 'https://www.icann.org/resources/pages/dnssec-2014-01-29-en' }
      ]
    },
    {
      id: 'vpn-vulnerabilities',
      name: 'VPN Security Weaknesses',
      category: 'network',
      severity: 'HIGH',
      description: 'VPN uses weak encryption, outdated protocols, or has configuration issues.',
      impact: 'Traffic decryption, unauthorized network access, credential theft, man-in-the-middle attacks.',
      detection: 'VPN protocol and cipher analysis',
      howToFix: [
        'Use modern VPN protocols (WireGuard, IKEv2)',
        'Disable legacy protocols (PPTP, L2TP without IPSec)',
        'Implement strong encryption (AES-256)',
        'Use certificate-based authentication',
        'Enable perfect forward secrecy',
        'Regular VPN security audits',
        'Implement VPN kill switch'
      ],
      resources: [
        { title: 'VPN Security Best Practices', url: 'https://www.nist.gov/publications/guide-ipsec-vpns' }
      ]
    },
    {
      id: 'mitm-vulnerability',
      name: 'Man-in-the-Middle Attack Surface',
      category: 'network',
      severity: 'HIGH',
      description: 'Network lacks protection against ARP spoofing, rogue DHCP, or SSL stripping.',
      impact: 'Traffic interception, credential theft, session hijacking, data manipulation.',
      detection: 'Network monitoring for ARP anomalies and rogue DHCP servers',
      howToFix: [
        'Implement ARP inspection (DAI) on switches',
        'Use DHCP snooping',
        'Enable 802.1X port authentication',
        'Implement HSTS to prevent SSL stripping',
        'Use certificate pinning for critical connections',
        'Deploy network intrusion detection (IDS/IPS)',
        'Regular network security monitoring'
      ],
      resources: [
        { title: 'MITM Attack Prevention', url: 'https://owasp.org/www-community/attacks/Man-in-the-middle_attack' }
      ]
    }
  ],

  // Cloud Security
  cloud: [
    {
      id: 'cloud-misconfig',
      name: 'Cloud Resource Misconfiguration',
      category: 'cloud',
      severity: 'CRITICAL',
      description: 'Cloud storage buckets, databases, or services are publicly accessible.',
      impact: 'Data breach, unauthorized access, data deletion, cryptocurrency mining, massive costs.',
      detection: 'Cloud security posture management tools (ScoutSuite, Prowler)',
      howToFix: [
        'Enable private access by default for all resources',
        'Use IAM policies with least privilege',
        'Enable bucket/blob encryption',
        'Implement cloud security posture management (CSPM)',
        'Regular security audits of cloud configurations',
        'Use infrastructure-as-code with security scanning',
        'Enable cloud provider security services (GuardDuty, Security Center)'
      ],
      resources: [
        { title: 'AWS Security Best Practices', url: 'https://aws.amazon.com/security/best-practices' },
        { title: 'Azure Security Benchmarks', url: 'https://docs.microsoft.com/en-us/security/benchmark/azure' },
        { title: 'GCP Security Best Practices', url: 'https://cloud.google.com/security/best-practices' }
      ]
    },
    {
      id: 'excessive-cloud-permissions',
      name: 'Excessive Cloud IAM Permissions',
      category: 'cloud',
      severity: 'HIGH',
      description: 'Cloud identities have overly broad permissions beyond what they need.',
      impact: 'Privilege escalation, lateral movement, resource abuse, data access beyond authorization.',
      detection: 'IAM policy analysis tools and access reviews',
      howToFix: [
        'Apply principle of least privilege',
        'Use role-based access control (RBAC)',
        'Implement just-in-time (JIT) access',
        'Regular access reviews and cleanup',
        'Use service accounts with minimal permissions',
        'Enable MFA for all accounts',
        'Monitor for unused permissions'
      ],
      resources: [
        { title: 'Cloud IAM Best Practices', url: 'https://cloud.google.com/iam/docs/best-practices' }
      ]
    },
    {
      id: 'cloud-api-key-exposure',
      name: 'Exposed Cloud API Keys',
      category: 'cloud',
      severity: 'CRITICAL',
      description: 'Cloud provider API keys committed to code repositories or exposed in logs.',
      impact: 'Complete cloud account compromise, resource abuse, data theft, massive financial costs.',
      detection: 'Secret scanning tools (GitGuardian, TruffleHog, git-secrets)',
      howToFix: [
        'Use secrets management services (AWS Secrets Manager, Azure Key Vault)',
        'Implement automated secret scanning in CI/CD',
        'Rotate keys regularly',
        'Use IAM roles instead of access keys when possible',
        'Enable CloudTrail/Activity Logs to detect key usage',
        'Revoke exposed keys immediately',
        'Add pre-commit hooks to prevent secret commits'
      ],
      resources: [
        { title: 'Secret Management Guide', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html' }
      ]
    },
    {
      id: 'serverless-security',
      name: 'Serverless Function Security Issues',
      category: 'cloud',
      severity: 'HIGH',
      description: 'Serverless functions lack proper input validation, logging, or security controls.',
      impact: 'Code injection, resource exhaustion, data leaks, unauthorized actions.',
      detection: 'Review function code and permissions for security gaps',
      howToFix: [
        'Implement input validation in all functions',
        'Use least privilege IAM roles per function',
        'Enable function-level logging and monitoring',
        'Implement rate limiting and timeout controls',
        'Scan function dependencies for vulnerabilities',
        'Use environment variables for secrets',
        'Regular security reviews of function code'
      ],
      resources: [
        { title: 'Serverless Security', url: 'https://owasp.org/www-project-serverless-top-10' }
      ]
    },
    {
      id: 'container-security',
      name: 'Container Security Vulnerabilities',
      category: 'cloud',
      severity: 'HIGH',
      description: 'Containers run with excessive privileges or contain vulnerable dependencies.',
      impact: 'Container escape, host compromise, lateral movement, privilege escalation.',
      detection: 'Container image scanning (Trivy, Clair, Snyk)',
      howToFix: [
        'Scan images for vulnerabilities before deployment',
        'Use minimal base images (Alpine, distroless)',
        'Run containers as non-root users',
        'Implement pod security policies/standards',
        'Use network policies to restrict traffic',
        'Enable runtime security monitoring',
        'Regular image updates and patches'
      ],
      resources: [
        { title: 'Container Security Best Practices', url: 'https://kubernetes.io/docs/concepts/security' },
        { title: 'CIS Docker Benchmark', url: 'https://www.cisecurity.org/benchmark/docker' }
      ]
    }
  ],

  // Modern Threat Intelligence & Attack Techniques
  threats: [
    {
      id: 'ransomware-attacks',
      name: 'Modern Ransomware Attacks',
      category: 'threats',
      severity: 'CRITICAL',
      description: 'Advanced ransomware strains using double extortion tactics and file encryption to extort victims.',
      impact: 'Complete data encryption, data exfiltration, business disruption, financial losses, regulatory penalties, reputational damage.',
      detection: 'Monitor for unusual file encryption activity, lateral movement, data exfiltration patterns, and known ransomware indicators of compromise (IOCs)',
      howToFix: [
        'Implement comprehensive offline backups (3-2-1 backup strategy)',
        'Deploy endpoint detection and response (EDR) solutions',
        'Use application whitelisting and least privilege access',
        'Enable and monitor email security (SPF, DKIM, DMARC)',
        'Regular security awareness training on phishing',
        'Network segmentation to limit lateral movement',
        'Keep systems patched and updated',
        'Develop and test incident response plans'
      ],
      resources: [
        { title: 'CISA Ransomware Guide', url: 'https://www.cisa.gov/stopransomware' },
        { title: 'No More Ransom Project', url: 'https://www.nomoreransom.org' }
      ]
    },
    {
      id: 'zero-day-exploits',
      name: 'Zero-Day Exploit Detection',
      category: 'threats',
      severity: 'CRITICAL',
      description: 'Previously unknown vulnerabilities actively exploited before patches are available.',
      impact: 'Remote code execution, privilege escalation, data breaches, complete system compromise.',
      detection: 'Behavioral analysis, anomaly detection, threat intelligence feeds, honeypots, and advanced EDR solutions',
      howToFix: [
        'Implement defense-in-depth security architecture',
        'Use virtual patching and WAF for critical systems',
        'Deploy advanced threat protection (ATP) solutions',
        'Subscribe to threat intelligence feeds',
        'Enable exploit mitigation technologies (DEP, ASLR, CFG)',
        'Rapid incident response capabilities',
        'Network traffic analysis and anomaly detection',
        'Regular vulnerability assessments'
      ],
      resources: [
        { title: 'MITRE ATT&CK Framework', url: 'https://attack.mitre.org' },
        { title: 'Zero Day Initiative', url: 'https://www.zerodayinitiative.com' }
      ]
    },
    {
      id: 'advanced-phishing',
      name: 'Advanced Phishing & Social Engineering',
      category: 'threats',
      severity: 'HIGH',
      description: 'Sophisticated spear-phishing, business email compromise (BEC), and deepfake-enabled social engineering attacks.',
      impact: 'Credential theft, wire fraud, data breaches, malware installation, business email compromise.',
      detection: 'Email authentication checks, anomaly detection in email patterns, user behavior analytics, AI-powered phishing detection',
      howToFix: [
        'Implement multi-factor authentication (MFA) everywhere',
        'Deploy email security solutions with AI detection',
        'Regular security awareness training with simulated phishing',
        'Verify unusual requests via secondary channels',
        'Use DMARC to prevent email spoofing',
        'Implement URL sandboxing and link analysis',
        'Monitor for credential leaks on dark web',
        'Establish verification procedures for financial transactions'
      ],
      resources: [
        { title: 'Anti-Phishing Working Group', url: 'https://apwg.org' },
        { title: 'NIST Phishing Guidance', url: 'https://www.nist.gov/itl/applied-cybersecurity/phishing' }
      ]
    },
    {
      id: 'supply-chain-attacks',
      name: 'Supply Chain & Third-Party Attacks',
      category: 'threats',
      severity: 'CRITICAL',
      description: 'Attacks targeting software supply chains, dependencies, and trusted third-party vendors.',
      impact: 'Widespread compromise, backdoor installation, data breaches across multiple organizations, loss of trust.',
      detection: 'Software composition analysis, dependency scanning, code signing verification, vendor security assessments',
      howToFix: [
        'Implement software bill of materials (SBOM)',
        'Verify digital signatures and checksums',
        'Use dependency scanning tools (Snyk, Dependabot)',
        'Vendor security questionnaires and audits',
        'Network segmentation for third-party access',
        'Monitor for suspicious updates or changes',
        'Implement zero-trust architecture',
        'Regular security assessments of supply chain'
      ],
      resources: [
        { title: 'NIST Supply Chain Security', url: 'https://www.nist.gov/itl/executive-order-improving-nations-cybersecurity/software-supply-chain-security-guidance' },
        { title: 'CISA Supply Chain Risk Management', url: 'https://www.cisa.gov/supply-chain' }
      ]
    },
    {
      id: 'fileless-malware',
      name: 'Fileless & Living-off-the-Land Attacks',
      category: 'threats',
      severity: 'HIGH',
      description: 'Memory-based malware and attacks using legitimate system tools (PowerShell, WMI, etc.) to evade detection.',
      impact: 'Undetected persistence, credential theft, lateral movement, data exfiltration, difficult forensics.',
      detection: 'Memory forensics, behavioral analysis, PowerShell logging, command-line auditing, EDR solutions',
      howToFix: [
        'Enable PowerShell script block logging',
        'Implement application whitelisting (AppLocker)',
        'Deploy memory protection and scanning',
        'Monitor command-line activity and arguments',
        'Restrict administrative tool access',
        'Use constrained language mode for PowerShell',
        'Enable Windows Defender Application Control (WDAC)',
        'Behavioral monitoring and anomaly detection'
      ],
      resources: [
        { title: 'MITRE ATT&CK: Living off the Land', url: 'https://attack.mitre.org/techniques/T1218' },
        { title: 'Fileless Malware Defense', url: 'https://www.sans.org/white-papers/fileless-malware' }
      ]
    },
    {
      id: 'apt-tactics',
      name: 'Advanced Persistent Threat (APT) Tactics',
      category: 'threats',
      severity: 'CRITICAL',
      description: 'Nation-state and organized cybercrime groups using advanced techniques for long-term access.',
      impact: 'Prolonged data theft, espionage, intellectual property theft, critical infrastructure compromise.',
      detection: 'Threat hunting, advanced analytics, network traffic analysis, endpoint telemetry, threat intelligence',
      howToFix: [
        'Implement comprehensive logging and SIEM',
        'Deploy deception technology (honeypots, honeytokens)',
        'Regular threat hunting activities',
        'Network segmentation and micro-segmentation',
        'Implement zero-trust network architecture',
        'Advanced endpoint protection with behavioral analysis',
        'Threat intelligence sharing and correlation',
        'Regular security assessments and red team exercises'
      ],
      resources: [
        { title: 'MITRE ATT&CK for Enterprise', url: 'https://attack.mitre.org/matrices/enterprise' },
        { title: 'APT Groups and Operations', url: 'https://attack.mitre.org/groups' }
      ]
    },
    {
      id: 'cryptojacking',
      name: 'Cryptojacking & Resource Hijacking',
      category: 'threats',
      severity: 'MEDIUM',
      description: 'Unauthorized use of computing resources to mine cryptocurrency or perform distributed computing.',
      impact: 'Performance degradation, increased costs, resource exhaustion, potential gateway to other attacks.',
      detection: 'Monitor CPU/GPU usage, network traffic to mining pools, browser extension analysis, process monitoring',
      howToFix: [
        'Deploy anti-cryptomining browser extensions',
        'Monitor and alert on unusual resource consumption',
        'Block known mining domains at firewall/DNS level',
        'Regular vulnerability scanning and patching',
        'Implement content security policies (CSP)',
        'Use ad blockers and script blockers',
        'Monitor cloud resource usage and alerts',
        'Educate users on cryptojacking risks'
      ],
      resources: [
        { title: 'Cryptojacking Prevention', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories' }
      ]
    },
    {
      id: 'botnet-ddos',
      name: 'Botnet & DDoS Attacks',
      category: 'threats',
      severity: 'HIGH',
      description: 'Distributed denial-of-service attacks using compromised devices (IoT botnets) to overwhelm targets.',
      impact: 'Service unavailability, revenue loss, reputational damage, ransom demands, resource exhaustion.',
      detection: 'Traffic pattern analysis, rate limiting triggers, anomaly detection, DDoS mitigation service alerts',
      howToFix: [
        'Implement DDoS protection services (Cloudflare, Akamai)',
        'Deploy rate limiting and traffic filtering',
        'Use content delivery networks (CDNs)',
        'Implement auto-scaling infrastructure',
        'Configure network-level DDoS mitigation',
        'Maintain incident response playbooks',
        'Monitor traffic patterns and establish baselines',
        'Secure IoT devices to prevent botnet recruitment'
      ],
      resources: [
        { title: 'CISA DDoS Quick Guide', url: 'https://www.cisa.gov/sites/default/files/publications/DDoS%20Quick%20Guide.pdf' },
        { title: 'Cloudflare DDoS Trends', url: 'https://radar.cloudflare.com/ddos' }
      ]
    },
    {
      id: 'ai-powered-attacks',
      name: 'AI-Powered & Automated Attacks',
      category: 'threats',
      severity: 'HIGH',
      description: 'Machine learning-enhanced attacks including deepfakes, automated vulnerability discovery, and adaptive malware.',
      impact: 'Highly convincing social engineering, rapid vulnerability exploitation, evasion of traditional defenses.',
      detection: 'AI-powered defense systems, deepfake detection tools, behavioral analysis, advanced threat intelligence',
      howToFix: [
        'Implement AI-powered security tools',
        'Use deepfake detection technologies',
        'Multi-factor authentication with biometrics',
        'Establish verification procedures for sensitive actions',
        'Deploy behavioral analytics and anomaly detection',
        'Regular security awareness training on AI threats',
        'Automated threat intelligence and response',
        'Continuous monitoring and adaptive defenses'
      ],
      resources: [
        { title: 'MITRE ATLAS - AI Threat Landscape', url: 'https://atlas.mitre.org' },
        { title: 'AI Security Best Practices', url: 'https://owasp.org/www-project-machine-learning-security-top-10' }
      ]
    },
    {
      id: 'insider-threats',
      name: 'Insider Threats & Privilege Abuse',
      category: 'threats',
      severity: 'HIGH',
      description: 'Malicious or negligent insiders misusing authorized access to steal data or cause harm.',
      impact: 'Data theft, sabotage, intellectual property loss, compliance violations, financial fraud.',
      detection: 'User behavior analytics (UBA), data loss prevention (DLP), privileged access monitoring, audit logging',
      howToFix: [
        'Implement least privilege access controls',
        'Deploy user behavior analytics (UBA)',
        'Use data loss prevention (DLP) solutions',
        'Monitor privileged account activity',
        'Implement separation of duties',
        'Regular access reviews and recertification',
        'Background checks and security clearances',
        'Exit procedures for departing employees'
      ],
      resources: [
        { title: 'CISA Insider Threat Mitigation', url: 'https://www.cisa.gov/topics/physical-security/insider-threat-mitigation' },
        { title: 'CERT Insider Threat Center', url: 'https://www.sei.cmu.edu/about/divisions/cert/index.cfm' }
      ]
    },
    {
      id: 'mobile-malware',
      name: 'Mobile Malware & App-Based Threats',
      category: 'threats',
      severity: 'MEDIUM',
      description: 'Malicious mobile apps, banking trojans, spyware, and SMS fraud targeting smartphones.',
      impact: 'Data theft, financial fraud, unauthorized access, privacy invasion, device compromise.',
      detection: 'Mobile device management (MDM), app store security, behavioral analysis, antivirus scanning',
      howToFix: [
        'Deploy mobile device management (MDM) solutions',
        'Use mobile threat defense (MTD) platforms',
        'Only install apps from official stores',
        'Review app permissions carefully',
        'Keep mobile OS and apps updated',
        'Use mobile antivirus and security apps',
        'Implement containerization for work data',
        'Enable remote wipe capabilities'
      ],
      resources: [
        { title: 'OWASP Mobile Security', url: 'https://owasp.org/www-project-mobile-security' },
        { title: 'NIST Mobile Device Security', url: 'https://www.nist.gov/programs-projects/mobile-device-security' }
      ]
    },
    {
      id: 'credential-stuffing',
      name: 'Credential Stuffing & Account Takeover',
      category: 'threats',
      severity: 'HIGH',
      description: 'Automated attacks using leaked credentials to compromise accounts through credential reuse.',
      impact: 'Account takeover, identity theft, financial fraud, data breaches, reputational damage.',
      detection: 'Failed login monitoring, impossible travel detection, device fingerprinting, CAPTCHA triggers',
      howToFix: [
        'Enforce multi-factor authentication (MFA)',
        'Implement rate limiting on login attempts',
        'Use CAPTCHA for suspicious activity',
        'Monitor for leaked credentials',
        'Implement password complexity requirements',
        'Use passwordless authentication where possible',
        'Deploy bot detection and mitigation',
        'Educate users on password hygiene and password managers'
      ],
      resources: [
        { title: 'OWASP Credential Stuffing Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html' },
        { title: 'Have I Been Pwned', url: 'https://haveibeenpwned.com' }
      ]
    }
  ]
};

/**
 * Security scanning checklists for different asset types
 */
export const scanningChecklists = {
  website: [
    { id: 'https', label: 'Uses HTTPS encryption', severity: 'CRITICAL' },
    { id: 'headers', label: 'Has security headers configured', severity: 'HIGH' },
    { id: 'cookies', label: 'Uses secure cookie settings', severity: 'MEDIUM' },
    { id: 'forms', label: 'Forms have CSRF protection', severity: 'MEDIUM' },
    { id: 'inputs', label: 'Input validation implemented', severity: 'HIGH' },
    { id: 'errors', label: 'Generic error messages (no stack traces)', severity: 'MEDIUM' },
    { id: 'version', label: 'Server version hidden', severity: 'LOW' },
    { id: 'robots', label: 'Sensitive paths excluded from crawling', severity: 'LOW' }
  ],
  email: [
    { id: 'spf', label: 'SPF record configured', severity: 'HIGH' },
    { id: 'dkim', label: 'DKIM signing enabled', severity: 'HIGH' },
    { id: 'dmarc', label: 'DMARC policy set', severity: 'HIGH' },
    { id: 'tls', label: 'TLS encryption for mail transport', severity: 'MEDIUM' },
    { id: 'relay', label: 'Not an open relay', severity: 'CRITICAL' },
    { id: 'blacklist', label: 'Not on email blacklists', severity: 'MEDIUM' }
  ],
  server: [
    { id: 'firewall', label: 'Firewall configured', severity: 'CRITICAL' },
    { id: 'ports', label: 'Only necessary ports open', severity: 'HIGH' },
    { id: 'updates', label: 'System is patched and updated', severity: 'CRITICAL' },
    { id: 'ssh', label: 'SSH secured (no root, key auth)', severity: 'HIGH' },
    { id: 'passwords', label: 'No default passwords', severity: 'CRITICAL' },
    { id: 'backups', label: 'Regular backups configured', severity: 'HIGH' },
    { id: 'logging', label: 'Security logging enabled', severity: 'MEDIUM' },
    { id: 'monitoring', label: 'Intrusion detection in place', severity: 'MEDIUM' }
  ],
  application: [
    { id: 'secrets', label: 'No hardcoded secrets', severity: 'CRITICAL' },
    { id: 'deps', label: 'Dependencies up to date', severity: 'HIGH' },
    { id: 'auth', label: 'Strong authentication', severity: 'CRITICAL' },
    { id: 'authz', label: 'Proper authorization checks', severity: 'CRITICAL' },
    { id: 'ratelimit', label: 'Rate limiting implemented', severity: 'MEDIUM' },
    { id: 'logging', label: 'No sensitive data in logs', severity: 'MEDIUM' },
    { id: 'validation', label: 'Input validation everywhere', severity: 'HIGH' },
    { id: 'encoding', label: 'Output encoding', severity: 'HIGH' }
  ],
  data: [
    { id: 'encryption', label: 'Data encrypted at rest', severity: 'CRITICAL' },
    { id: 'transit', label: 'Data encrypted in transit', severity: 'CRITICAL' },
    { id: 'passwords', label: 'Passwords properly hashed', severity: 'CRITICAL' },
    { id: 'access', label: 'Access controls implemented', severity: 'HIGH' },
    { id: 'backup', label: 'Backups are encrypted', severity: 'HIGH' },
    { id: 'retention', label: 'Data retention policy defined', severity: 'MEDIUM' },
    { id: 'minimal', label: 'Data minimization practiced', severity: 'MEDIUM' }
  ],
  finance: [
    { id: 'pci', label: 'PCI DSS compliant payment processing', severity: 'CRITICAL' },
    { id: 'tokenization', label: 'Payment data tokenized', severity: 'CRITICAL' },
    { id: 'api-auth', label: 'Strong API authentication', severity: 'CRITICAL' },
    { id: 'txn-signing', label: 'Transaction signing implemented', severity: 'HIGH' },
    { id: 'mfa-finance', label: 'MFA for high-value transactions', severity: 'HIGH' },
    { id: 'kyc', label: 'KYC/AML controls in place', severity: 'HIGH' },
    { id: 'fraud-detection', label: 'Real-time fraud monitoring', severity: 'MEDIUM' }
  ],
  iot: [
    { id: 'unique-creds', label: 'Unique credentials per device', severity: 'CRITICAL' },
    { id: 'firmware-signing', label: 'Firmware updates signed', severity: 'CRITICAL' },
    { id: 'secure-boot', label: 'Secure boot enabled', severity: 'HIGH' },
    { id: 'debug-disabled', label: 'Debug interfaces disabled', severity: 'HIGH' },
    { id: 'encrypted-comms', label: 'Encrypted communications', severity: 'HIGH' },
    { id: 'network-seg', label: 'IoT network segmentation', severity: 'MEDIUM' },
    { id: 'privacy', label: 'Privacy-by-design implemented', severity: 'MEDIUM' }
  ],
  network: [
    { id: 'wifi-wpa3', label: 'WPA3 or WPA2 WiFi security', severity: 'HIGH' },
    { id: 'segmentation', label: 'Network segmentation in place', severity: 'HIGH' },
    { id: 'dnssec', label: 'DNSSEC enabled', severity: 'MEDIUM' },
    { id: 'vpn-secure', label: 'Secure VPN configuration', severity: 'HIGH' },
    { id: 'ids-ips', label: 'Intrusion detection/prevention', severity: 'MEDIUM' },
    { id: 'arp-protection', label: 'ARP spoofing protection', severity: 'MEDIUM' },
    { id: 'monitoring', label: 'Network traffic monitoring', severity: 'MEDIUM' }
  ],
  cloud: [
    { id: 'private-access', label: 'Resources not publicly exposed', severity: 'CRITICAL' },
    { id: 'least-privilege', label: 'Least privilege IAM policies', severity: 'CRITICAL' },
    { id: 'secrets-mgmt', label: 'Secrets in vault/manager', severity: 'CRITICAL' },
    { id: 'cloud-logging', label: 'Cloud audit logging enabled', severity: 'HIGH' },
    { id: 'encryption', label: 'Data encrypted at rest', severity: 'HIGH' },
    { id: 'mfa-cloud', label: 'MFA enabled for all accounts', severity: 'HIGH' },
    { id: 'cspm', label: 'Security posture monitoring', severity: 'MEDIUM' }
  ],
  threats: [
    { id: 'backups', label: 'Offline backups for ransomware protection', severity: 'CRITICAL' },
    { id: 'edr', label: 'Endpoint detection and response deployed', severity: 'CRITICAL' },
    { id: 'patch-mgmt', label: 'Regular patching against zero-days', severity: 'CRITICAL' },
    { id: 'mfa-everywhere', label: 'MFA on all accounts', severity: 'CRITICAL' },
    { id: 'phishing-training', label: 'Regular security awareness training', severity: 'HIGH' },
    { id: 'threat-intel', label: 'Threat intelligence feeds monitored', severity: 'HIGH' },
    { id: 'incident-response', label: 'Incident response plan tested', severity: 'HIGH' },
    { id: 'network-monitoring', label: 'Network traffic analysis enabled', severity: 'MEDIUM' }
  ]
};

/**
 * Learning modules for security education
 */
export const learningModules = [
  {
    id: 'web-security-basics',
    title: 'Web Security Basics',
    description: 'Learn the fundamentals of web application security',
    topics: ['HTTPS', 'Security Headers', 'OWASP Top 10'],
    duration: '30 min',
    level: 'Beginner'
  },
  {
    id: 'email-authentication',
    title: 'Email Authentication',
    description: 'Understanding SPF, DKIM, and DMARC',
    topics: ['SPF Records', 'DKIM Signing', 'DMARC Policies'],
    duration: '25 min',
    level: 'Intermediate'
  },
  {
    id: 'server-hardening',
    title: 'Server Hardening',
    description: 'Secure your servers against attacks',
    topics: ['Firewall Configuration', 'SSH Security', 'Patch Management'],
    duration: '45 min',
    level: 'Intermediate'
  },
  {
    id: 'secure-coding',
    title: 'Secure Coding Practices',
    description: 'Write code that resists attacks',
    topics: ['Input Validation', 'Output Encoding', 'Authentication'],
    duration: '60 min',
    level: 'Intermediate'
  },
  {
    id: 'data-protection',
    title: 'Data Protection',
    description: 'Protect sensitive data at rest and in transit',
    topics: ['Encryption', 'Key Management', 'Access Control'],
    duration: '40 min',
    level: 'Advanced'
  },
  {
    id: 'financial-security',
    title: 'Financial Systems Security',
    description: 'Secure payment processing and financial APIs',
    topics: ['PCI DSS Compliance', 'Payment Tokenization', 'Transaction Security', 'Fraud Prevention'],
    duration: '75 min',
    level: 'Advanced'
  },
  {
    id: 'iot-pentesting',
    title: 'IoT Device Pentesting',
    description: 'Learn to assess security of IoT and smart devices',
    topics: ['Firmware Analysis', 'Hardware Hacking', 'IoT Protocols', 'Smart Home Security'],
    duration: '90 min',
    level: 'Advanced'
  },
  {
    id: 'network-pentesting',
    title: 'Network Penetration Testing',
    description: 'Master network security assessment techniques',
    topics: ['WiFi Security', 'Network Scanning', 'MITM Attacks', 'VPN Analysis'],
    duration: '120 min',
    level: 'Advanced'
  },
  {
    id: 'cloud-security',
    title: 'Cloud Security & Pentesting',
    description: 'Secure cloud infrastructure and services',
    topics: ['AWS/Azure/GCP Security', 'IAM Policies', 'Container Security', 'Serverless Security'],
    duration: '90 min',
    level: 'Advanced'
  },
  {
    id: 'retail-security',
    title: 'E-Commerce & Retail Security',
    description: 'Protect online retail platforms and POS systems',
    topics: ['Payment Security', 'Customer Data Protection', 'Inventory Systems', 'Supply Chain Security'],
    duration: '60 min',
    level: 'Intermediate'
  },
  {
    id: 'api-security',
    title: 'API Security Testing',
    description: 'Comprehensive API penetration testing',
    topics: ['REST/GraphQL Security', 'Authentication Testing', 'Rate Limiting', 'API Fuzzing'],
    duration: '75 min',
    level: 'Advanced'
  },
  {
    id: 'wireless-security',
    title: 'Wireless Network Security',
    description: 'WiFi and wireless protocol security assessment',
    topics: ['WPA3 Security', 'Evil Twin Attacks', 'Wireless Encryption', 'Bluetooth Security'],
    duration: '60 min',
    level: 'Intermediate'
  },
  {
    id: 'cryptocurrency-security',
    title: 'Cryptocurrency & Blockchain Security',
    description: 'Secure cryptocurrency systems and smart contracts',
    topics: ['Wallet Security', 'Smart Contract Auditing', 'Exchange Security', 'DeFi Risks'],
    duration: '90 min',
    level: 'Advanced'
  },
  {
    id: 'social-engineering',
    title: 'Social Engineering & Phishing',
    description: 'Understanding and preventing social engineering attacks',
    topics: ['Phishing Detection', 'Pretexting', 'Security Awareness', 'Human Factors'],
    duration: '45 min',
    level: 'Beginner'
  },
  {
    id: 'incident-response',
    title: 'Incident Response & Forensics',
    description: 'Respond to and investigate security incidents',
    topics: ['Breach Detection', 'Evidence Collection', 'Threat Hunting', 'Recovery Procedures'],
    duration: '120 min',
    level: 'Advanced'
  },
  {
    id: 'compliance-frameworks',
    title: 'Security Compliance Frameworks',
    description: 'Navigate PCI DSS, GDPR, SOC 2, and other standards',
    topics: ['PCI DSS', 'GDPR', 'HIPAA', 'SOC 2', 'ISO 27001'],
    duration: '90 min',
    level: 'Intermediate'
  },
  {
    id: 'modern-threats',
    title: 'Modern Threat Landscape',
    description: 'Current hacking techniques and attack methods',
    topics: ['Ransomware Tactics', 'Zero-Day Exploits', 'APT Techniques', 'Fileless Malware'],
    duration: '90 min',
    level: 'Advanced'
  },
  {
    id: 'malware-analysis',
    title: 'Malware Analysis & Reverse Engineering',
    description: 'Analyze and reverse engineer malicious software',
    topics: ['Static Analysis', 'Dynamic Analysis', 'Malware Families', 'Behavioral Analysis'],
    duration: '120 min',
    level: 'Advanced'
  },
  {
    id: 'threat-hunting',
    title: 'Threat Hunting & Detection',
    description: 'Proactive threat detection and hunting techniques',
    topics: ['Threat Intelligence', 'MITRE ATT&CK', 'IOC Analysis', 'Behavioral Analytics'],
    duration: '90 min',
    level: 'Advanced'
  },
  {
    id: 'defensive-security',
    title: 'Defensive Security Operations',
    description: 'Build and operate security defenses',
    topics: ['SIEM Operations', 'EDR/XDR', 'Threat Detection', 'Security Automation'],
    duration: '120 min',
    level: 'Advanced'
  },
  {
    id: 'cybercrime-trends',
    title: 'Cybercrime & Fraud Prevention',
    description: 'Combat fraud, cyber bullying, and online threats',
    topics: ['Online Fraud Detection', 'Identity Theft Prevention', 'Cyber Bullying Response', 'Digital Forensics'],
    duration: '75 min',
    level: 'Intermediate'
  }
];

export default {
  vulnerabilityCategories,
  severityLevels,
  vulnerabilityDatabase,
  scanningChecklists,
  learningModules
};
