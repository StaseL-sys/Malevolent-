# Contributing to Malevolent-

Thank you for your interest in contributing to Malevolent-! Together, we can make this project a powerful resource for security learning and the cybersecurity community. 

We welcome contributions of all kinds: code, documentation, bug reports, feature requests, and community engagement.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [How You Can Contribute](#how-you-can-contribute)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Community and Support](#community-and-support)

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## How You Can Contribute

### 🐛 Report Bugs
Found a bug? Help us fix it!
- Search existing issues to avoid duplicates
- Use the issue template if available
- Provide clear reproduction steps
- Include environment details (OS, Node version, browser)

### 💡 Suggest Features
Have an idea to improve the project?
- Check if it's already suggested in issues or discussions
- Explain the use case and benefits
- Consider how it fits the educational mission

### 📝 Improve Documentation
Documentation is crucial for learning!
- Fix typos or unclear explanations
- Add examples or tutorials
- Improve setup instructions
- Enhance code comments

### 🔧 Fix Bugs or Add Features
Ready to code? Great!
- Look for issues labeled `good first issue` or `help wanted`
- Comment on the issue to claim it
- Follow the development workflow below

### 🎓 Share Knowledge
Help others learn:
- Answer questions in GitHub Discussions
- Write blog posts or tutorials
- Create video walkthroughs
- Share on social media

## Getting Started

### Prerequisites
- Node.js 18+ and npm
- Git
- A code editor (VS Code recommended)

### Setup
1. **Fork the repository** on GitHub
2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR-USERNAME/Malevolent-.git
   cd Malevolent-/security-scanner
   ```

3. **Install dependencies**:
   ```bash
   npm install
   ```

4. **Start the development server**:
   ```bash
   npm run dev
   ```

5. **Verify everything works**:
   - Open http://localhost:5173
   - Run tests: `npm test`
   - Run linter: `npm run lint`

## Development Workflow

1. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-number-description
   ```

2. **Make your changes**:
   - Write clean, readable code
   - Follow existing code style
   - Add tests for new features
   - Update documentation as needed

3. **Test your changes**:
   ```bash
   npm run lint        # Check code style
   npm test           # Run unit tests
   npm run build      # Ensure it builds
   ```

4. **Commit your changes**:
   ```bash
   git add .
   git commit -m "Brief description of changes"
   ```
   
   Use clear commit messages:
   - `feat: add new vulnerability check for XSS`
   - `fix: correct HTTPS validation logic`
   - `docs: update installation instructions`
   - `test: add tests for email security scanner`

5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request** on GitHub

## Coding Standards

### General Principles
- **Clarity over cleverness**: Write code that's easy to understand
- **Educational focus**: Remember this is a learning platform
- **Security first**: Follow secure coding practices
- **Consistency**: Match the existing code style

### JavaScript/React Guidelines
- Use modern ES6+ syntax
- Prefer functional components and hooks
- Use meaningful variable and function names
- Keep functions small and focused
- Add JSDoc comments for complex functions
- Avoid deep nesting (max 3 levels)

### File Organization
- Place components in `src/components/`
- Keep related files together
- Use index files for cleaner imports
- Separate concerns (UI, logic, data)

### Security Considerations
- Never commit secrets or API keys
- Sanitize user inputs
- Follow OWASP guidelines
- Document security implications

## Testing Guidelines

### Writing Tests
- Write tests for new features
- Maintain or improve code coverage
- Test edge cases and error conditions
- Use descriptive test names

### Running Tests
```bash
npm test              # Run all tests
npm test -- --watch   # Watch mode
npm test -- --coverage # With coverage
```

### Test Structure
```javascript
describe('Component or Feature', () => {
  it('should do something specific', () => {
    // Arrange
    // Act
    // Assert
  });
});
```

## Pull Request Process

### Before Submitting
- [ ] Code follows project style guidelines
- [ ] Tests pass locally (`npm test`)
- [ ] Linter passes (`npm run lint`)
- [ ] Build succeeds (`npm run build`)
- [ ] Documentation updated if needed
- [ ] Commits are clean and well-described

### PR Description
Include:
- **What**: Brief description of changes
- **Why**: Problem being solved or feature being added
- **How**: Approach taken (if non-obvious)
- **Testing**: How you tested the changes
- **Screenshots**: For UI changes

### Review Process
1. Maintainers will review your PR
2. Address any feedback or requested changes
3. Once approved, a maintainer will merge

### After Merging
- Your contribution will be recognized!
- Delete your feature branch
- Pull the latest changes from main

## Community and Support

### Communication Channels
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions, ideas, and general discussion
- **Pull Requests**: Code contributions and reviews

### Getting Help
- Check existing documentation first
- Search closed issues for similar problems
- Ask in GitHub Discussions
- Be patient and respectful

### Recognition
We value all contributions! Contributors will be:
- Listed in release notes
- Mentioned in project updates
- Added to contributors list

### First-Time Contributors
New to open source? Welcome! 
- Start with issues labeled `good first issue`
- Don't hesitate to ask questions
- Learn by doing - it's okay to make mistakes
- We're here to help you succeed!

## Questions?

If you have questions about contributing, feel free to:
- Open a discussion on GitHub
- Comment on a relevant issue
- Reach out to the maintainers

Thank you for contributing to Malevolent- and helping make cybersecurity education accessible to all! 🔒🎓