# Copilot Instructions for Malevolent Security Scanner

## Project Overview

This is an educational cybersecurity platform designed to help aspiring security professionals learn penetration testing, vulnerability assessment, and modern threat defense. The project includes:

- A comprehensive security scanner for 10 different asset types (Website, Email, Server, Application, Data, Finance, IoT, Network, Cloud, Threat Defense)
- A knowledge base covering 60+ vulnerabilities and modern threats
- 21 structured learning modules for cybersecurity education
- Interactive checklists for security assessments

**Educational Purpose:** This tool is strictly for educational purposes. All contributions should maintain the educational focus and ethical guidelines.

## Project Structure

```
Malevolent-/
├── .github/               # GitHub configuration and Copilot instructions
├── security-scanner/      # Main React application
│   ├── src/
│   │   ├── components/    # React components (ScannerForm, SecurityReport, VulnerabilityLibrary, etc.)
│   │   ├── data/          # Security knowledge base and vulnerability data
│   │   ├── services/      # Business logic (scannerService.js)
│   │   ├── test/          # Test files
│   │   ├── App.jsx        # Main application component
│   │   └── main.jsx       # Application entry point
│   ├── public/            # Static assets
│   ├── package.json       # Dependencies and scripts
│   ├── vite.config.js     # Vite configuration
│   └── eslint.config.js   # ESLint configuration
├── README.md              # Project documentation
├── CONTRIBUTING.md        # Contribution guidelines
└── CODE_OF_CONDUCT.md     # Code of conduct
```

## Technology Stack

- **React 19**: UI framework
- **Vite 7**: Build tool and development server
- **Vitest 4**: Testing framework
- **ESLint**: Code linting with React-specific rules

## Development Workflow

### Setup and Installation

```bash
cd security-scanner
npm install
```

### Development Commands

- **Start dev server**: `npm run dev` (runs on http://localhost:5173)
- **Build for production**: `npm run build`
- **Run tests**: `npm run test`
- **Watch tests**: `npm run test:watch`
- **Lint code**: `npm run lint`

### Testing Guidelines

- All new features should include tests
- Tests are located in `src/test/`
- Use Vitest with jsdom environment
- Test setup is in `src/test/setup.js`
- Run tests before submitting PRs
- Existing test files:
  - `securityKnowledge.test.js` - Tests for vulnerability data
  - `scannerService.test.js` - Tests for scanning logic

## Coding Standards and Conventions

### JavaScript/React Standards

- Use modern ES6+ syntax
- Use functional components with hooks (not class components)
- Use JSX for React components
- Follow React 19 best practices
- File naming: Use PascalCase for components (e.g., `ScannerForm.jsx`), camelCase for services (e.g., `scannerService.js`)
- Component files should use `.jsx` extension
- Service/utility files should use `.js` extension

### ESLint Configuration

- Uses `@eslint/js` recommended rules
- React Hooks plugin with recommended rules
- React Refresh plugin for Vite
- ECMAScript 2020/latest
- Unused variables allowed if they match pattern `^[A-Z_]` (constants)
- Ignore `dist` folder

### Code Quality

- Write clean, readable code with clear variable names
- Add comments only when necessary to explain complex logic
- Avoid console.log statements in production code
- Handle errors gracefully
- Validate user inputs

## Security and Educational Guidelines

### Security Considerations

- **Never include real credentials or API keys**
- **Never include malicious code or exploits**
- **Avoid code that could be used for unauthorized access**
- All security examples must be educational and ethical
- Include appropriate warnings and disclaimers
- Follow responsible disclosure practices

### Educational Focus

- Maintain the educational purpose in all features
- Provide clear explanations and remediation guidance
- Include links to external resources (OWASP, NIST, MITRE ATT&CK, CISA)
- Use severity ratings (Critical, High, Medium, Low)
- Focus on helping users learn security concepts

## Feature Areas

### Security Domains

When working on security-related features, understand these domains:

1. **Website Security**: HTTPS, headers, cookies, XSS, CSRF, SQL injection
2. **Email Security**: SPF, DKIM, DMARC, TLS, relay protection
3. **Server Security**: Firewall, ports, SSH, patches, backups
4. **Application Security**: Secrets, dependencies, auth, rate limiting
5. **Data Security**: Encryption, access control, password hashing
6. **Finance Security**: PCI DSS, payment tokenization, KYC/AML
7. **IoT Security**: Firmware updates, default credentials, network isolation
8. **Network Security**: WiFi, VPN, DNS, segmentation, MITM protection
9. **Cloud Security**: IAM, misconfigurations, containers, serverless
10. **Threat Defense**: Ransomware, zero-days, APTs, phishing, malware

### Components

- **ScannerForm**: User input forms for security assessments
- **SecurityReport**: Display scan results with grades and findings
- **VulnerabilityLibrary**: Browse and learn about vulnerabilities
- **Learning Modules**: Educational courses and content

## Common Tasks and Patterns

### Adding New Vulnerabilities

1. Update `src/data/securityKnowledge.js`
2. Include: name, description, severity, impact, remediation steps, resources
3. Add corresponding tests in `src/test/securityKnowledge.test.js`

### Adding New Security Checks

1. Update `src/services/scannerService.js`
2. Follow existing patterns for check functions
3. Return findings with severity, title, description, remediation
4. Add tests in `src/test/scannerService.test.js`

### Adding New Components

1. Create new `.jsx` file in `src/components/`
2. Use functional components with hooks
3. Follow React 19 patterns
4. Import and use in `App.jsx` or parent component

## Documentation

- Update README.md for major feature changes
- Keep CONTRIBUTING.md current
- Document complex functions and logic
- Include JSDoc comments for exported functions

## Pull Request Guidelines

- Keep changes focused and minimal
- Write clear commit messages
- Ensure all tests pass (`npm run test`)
- Ensure linting passes (`npm run lint`)
- Test the application locally (`npm run dev`)
- Include screenshots for UI changes
- Reference related issues

## Build and Deployment

- Production builds go to `dist/` folder
- Vite handles bundling and optimization
- Assets are fingerprinted for caching
- Preview builds with `npm run preview`

## License and Legal

- Licensed under Mozilla Public License 2.0
- All contributions must comply with MPL 2.0
- Maintain educational disclaimer in documentation
- Respect privacy and data protection laws

## Getting Help

- Review existing code in similar features
- Check CONTRIBUTING.md for general guidelines
- Reference the README.md for feature documentation
- Look at existing tests for testing patterns
