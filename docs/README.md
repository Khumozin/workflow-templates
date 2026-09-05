# DevSecOps Pipeline Documentation

This directory contains comprehensive DevSecOps pipeline guides for different application stacks. Each guide includes detailed pipeline architectures, security best practices, code examples, and implementation strategies.

## Available Guides

### 1. [Angular Applications](devsecops-angular-pipeline.md)
**Target**: Frontend Single Page Applications built with Angular

**Key Features**:
- Secret scanning with Gitleaks and GitGuardian
- ESLint security rules
- SonarCloud SAST analysis
- Dependency vulnerability scanning with Snyk
- Unit and E2E testing with Cypress
- Container security with Trivy
- Secure nginx configuration
- Content Security Policy implementation

**Security Focus**:
- XSS prevention
- CSRF protection
- Input sanitization
- Session management
- Browser security headers

---

### 2. [NestJS Applications](devsecops-nestjs-pipeline.md)
**Target**: Backend REST APIs built with NestJS/Node.js

**Key Features**:
- Secret scanning for API keys and database credentials
- ESLint with security plugins
- API security testing with OWASP ZAP
- SQL injection prevention
- Authentication/authorization testing
- Database migration testing
- Rate limiting implementation
- Structured logging

**Security Focus**:
- JWT security
- Password hashing (bcrypt)
- SQL injection prevention
- Input validation with class-validator
- API rate limiting
- CORS configuration
- Session management

---

### 3. [.NET Web APIs](devsecops-dotnet-pipeline.md)
**Target**: Backend REST APIs built with ASP.NET Core

**Key Features**:
- Code formatting with dotnet-format
- Security Code Scan analyzer
- SonarCloud with .NET analyzers
- NuGet vulnerability scanning
- Entity Framework migration testing
- Container security scanning
- Strong cryptography practices
- Application Insights integration

**Security Focus**:
- SQL injection prevention (EF Core)
- Password hashing (ASP.NET Identity)
- AES-256 encryption
- HTTPS enforcement
- Anti-forgery tokens
- Role-based access control
- Security analyzers (CA rules)

---

## Common Pipeline Stages

All three pipelines follow a similar DevSecOps structure:

```
┌─────────────────────────────────────────────────────┐
│ 1. Secret Scanning (Gitleaks, GitGuardian)         │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│ 2. Code Quality & Linting                           │
│    - Static analysis                                │
│    - Code formatting                                │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│ 3. SAST (SonarCloud, Security Analyzers)           │
│    - Vulnerability detection                        │
│    - Code smells                                    │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│ 4. Dependency Scanning (Snyk, npm audit)           │
│    - Known vulnerabilities                          │
│    - License compliance                             │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│ 5. Unit Tests                                       │
│    - Security-focused test cases                    │
│    - Code coverage (80%+)                           │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│ 6. Integration Tests                                │
│    - API endpoint testing                           │
│    - Database integration                           │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│ 7. E2E/DAST Testing                                 │
│    - Complete workflows                             │
│    - OWASP ZAP scanning                            │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│ 8. Build & Container Security                      │
│    - Docker image build                             │
│    - Trivy/Grype scanning                          │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│ 9. Release & Deployment                             │
│    - Semantic versioning                            │
│    - Automated deployment                           │
└─────────────────────────────────────────────────────┘
```

## Security Tools Matrix

| Tool | Angular | NestJS | .NET | Purpose |
|------|---------|--------|------|---------|
| **Gitleaks** | ✅ | ✅ | ✅ | Secret detection |
| **GitGuardian** | ✅ | ✅ | ✅ | Advanced secret scanning |
| **SonarCloud** | ✅ | ✅ | ✅ | SAST analysis |
| **Snyk** | ✅ | ✅ | ✅ | Dependency scanning |
| **Trivy** | ✅ | ✅ | ✅ | Container scanning |
| **OWASP ZAP** | ❌ | ✅ | ✅ | DAST API testing |
| **Cypress** | ✅ | ❌ | ❌ | E2E testing |
| **ESLint Security** | ✅ | ✅ | ❌ | JS/TS security linting |
| **Security Code Scan** | ❌ | ❌ | ✅ | .NET security analyzer |
| **npm audit** | ✅ | ✅ | ❌ | npm vulnerability check |
| **dotnet list package** | ❌ | ❌ | ✅ | NuGet vulnerability check |

## Quick Start

### For Angular Projects
```bash
# Use the Angular workflows
- uses: ./.github/workflows/angular-lint-app.yml
- uses: ./.github/workflows/angular-unit-test-app.yml
- uses: ./.github/workflows/angular-build-app.yml
- uses: ./.github/workflows/angular-cypress-e2e-test-app.yml
```

### For NestJS Projects
```bash
# Use Node.js workflows
- uses: ./.github/workflows/nodejs-dependency-analysis.yml
- uses: ./.github/workflows/sonar-cloud-static-code-analysis.yml
- uses: ./.github/workflows/nodejs-semantic-release.yml
```

### For .NET Projects
```bash
# Create custom .NET workflows based on documentation
# See devsecops-dotnet-pipeline.md for complete examples
```

## Security Best Practices

### 1. **Never Commit Secrets**
- Use GitHub Secrets for all sensitive data
- Scan for secrets before commits (pre-commit hooks)
- Rotate credentials regularly

### 2. **Fail Fast**
- Stop pipeline on critical vulnerabilities
- Set coverage thresholds (80%+)
- Enforce security gates

### 3. **Least Privilege**
- Use minimal permissions for workflows
- Run containers as non-root users
- Implement RBAC for deployments

### 4. **Defense in Depth**
- Multiple layers of security testing
- SAST + DAST + Container scanning
- Runtime monitoring

### 5. **Continuous Monitoring**
- Track security metrics
- Set up alerts for vulnerabilities
- Regular dependency updates

## Required GitHub Secrets

Configure these secrets in your repository settings:

### Common Secrets
```yaml
GITHUB_TOKEN              # Auto-provided by GitHub
GITGUARDIAN_API_KEY       # GitGuardian API key
SONAR_TOKEN               # SonarCloud authentication
SONAR_ORGANIZATION        # SonarCloud organization
SONAR_PROJECT_KEY         # SonarCloud project identifier
SONAR_URL                 # SonarCloud URL (usually https://sonarcloud.io)
SNYK_TOKEN                # Snyk API token
DOCKER_USERNAME           # Docker Hub username
DOCKER_PASSWORD           # Docker Hub password/token
```

### Application-Specific Secrets
```yaml
# Database
DATABASE_URL              # Connection string
REDIS_URL                 # Redis connection

# AWS (if deploying to AWS)
AWS_ACCESS_KEY_ID         # AWS credentials
AWS_SECRET_ACCESS_KEY     # AWS secret key

# Azure (if deploying to Azure)
AZURE_CREDENTIALS         # Azure service principal
```

## Pipeline Metrics & KPIs

Track these metrics for your DevSecOps maturity:

| Metric | Target | Description |
|--------|--------|-------------|
| **Pipeline Success Rate** | > 95% | Percentage of successful builds |
| **Time to Detect Vulnerabilities** | < 24h | From commit to detection |
| **Time to Remediate Critical Issues** | < 48h | From detection to fix deployed |
| **Code Coverage** | > 80% | Unit test coverage |
| **Security Issues per Release** | < 5 | High/Critical vulnerabilities |
| **Dependency Freshness** | > 90% | Packages within 6 months of latest |
| **Pipeline Duration** | < 15min | Total CI/CD execution time |
| **Failed Security Scans** | 0 | Zero tolerance for critical issues |

## Compliance & Standards

These pipelines help achieve compliance with:

- ✅ **OWASP Top 10** - Web application security risks
- ✅ **CWE Top 25** - Common weakness enumeration
- ✅ **SANS Top 25** - Most dangerous software errors
- ✅ **PCI DSS** - Payment card security standards
- ✅ **SOC 2** - Security and availability controls
- ✅ **ISO 27001** - Information security management
- ✅ **NIST** - Cybersecurity framework

## Additional Resources

### Documentation
- [GitHub Actions Documentation](https://docs.github.com/actions)
- [OWASP DevSecOps Guidelines](https://owasp.org/www-project-devsecops-guideline/)
- [SonarCloud Documentation](https://docs.sonarcloud.io/)
- [Snyk Documentation](https://docs.snyk.io/)

### Security Tools
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Trivy](https://github.com/aquasecurity/trivy)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Cypress Security](https://docs.cypress.io/guides/references/best-practices#Security)

### Learning
- [DevSecOps Manifesto](https://www.devsecops.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Microsoft Security Development Lifecycle](https://www.microsoft.com/en-us/securityengineering/sdl/)

## Support & Contribution

For issues or improvements:
1. Open an issue in the repository
2. Submit a pull request with enhancements
3. Share your pipeline improvements

## License

These workflows and documentation are provided as examples and templates. Adapt them to your specific security requirements and organizational policies.

---

**Last Updated**: 2025-12-02
**Version**: 1.0.0
