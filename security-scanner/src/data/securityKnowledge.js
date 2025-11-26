/**
 * Security Knowledge Base
 * Contains vulnerability definitions, detection patterns, and remediation guides
 */

export const vulnerabilityCategories = {
  WEBSITE: 'website',
  EMAIL: 'email',
  SERVER: 'server',
  APPLICATION: 'application',
  DATA: 'data'
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
  }
];

export default {
  vulnerabilityCategories,
  severityLevels,
  vulnerabilityDatabase,
  scanningChecklists,
  learningModules
};
