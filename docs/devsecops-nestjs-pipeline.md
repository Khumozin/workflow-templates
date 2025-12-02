# DevSecOps Pipeline for NestJS Applications

## Overview

This guide provides a comprehensive DevSecOps pipeline implementation for NestJS backend applications using GitHub Actions. The pipeline emphasizes API security, authentication/authorization testing, and backend-specific vulnerabilities.

## Pipeline Architecture

```mermaid
flowchart TB
    Start([Developer Push/PR]) --> Checkout[Checkout Code]

    Checkout --> SecretScan[Secret Scanning]
    SecretScan --> |Gitleaks/GitGuardian| SecretCheck{Secrets Found?}
    SecretCheck --> |Yes| Fail1[❌ Pipeline Fails]
    SecretCheck --> |No| Parallel

    Parallel --> Lint[Linting & Format]
    Parallel --> SAST[SAST Analysis]
    Parallel --> Deps[Dependency Check]
    Parallel --> DAST[API Security Testing]

    Lint --> |ESLint/Prettier| LintCheck{Issues?}
    LintCheck --> |Critical| Fail2[❌ Pipeline Fails]
    LintCheck --> |Pass| UnitTest

    SAST --> |SonarCloud| SASTCheck{Vulnerabilities?}
    SASTCheck --> |Critical| Fail3[❌ Pipeline Fails]
    SASTCheck --> |Pass| UnitTest

    Deps --> |Snyk| DepsCheck{Vulnerabilities?}
    DepsCheck --> |High/Critical| Fail4[❌ Pipeline Fails]
    DepsCheck --> |Pass| UnitTest

    DAST --> |OWASP ZAP| DASTCheck{API Vulns?}
    DASTCheck --> |High| Fail9[❌ Pipeline Fails]
    DASTCheck --> |Pass| UnitTest

    UnitTest[Unit Tests] --> UnitCheck{Tests Pass?}
    UnitCheck --> |No| Fail5[❌ Pipeline Fails]
    UnitCheck --> |Yes| Coverage{Coverage > 85%?}
    Coverage --> |No| Fail10[❌ Pipeline Fails]
    Coverage --> |Yes| IntegrationTest

    IntegrationTest[Integration Tests] --> IntCheck{Tests Pass?}
    IntCheck --> |No| Fail6[❌ Pipeline Fails]
    IntCheck --> |Yes| E2E

    E2E[E2E API Tests] --> E2ECheck{Tests Pass?}
    E2ECheck --> |No| Fail7[❌ Pipeline Fails]
    E2ECheck --> |Yes| Build

    Build[Build Application] --> BuildCheck{Build Success?}
    BuildCheck --> |No| Fail8[❌ Pipeline Fails]
    BuildCheck --> |Yes| ContainerScan

    ContainerScan[Container Security Scan] --> ContainerCheck{Vulnerabilities?}
    ContainerCheck --> |Critical/High| Fail11[❌ Pipeline Fails]
    ContainerCheck --> |Pass| DatabaseMigration

    DatabaseMigration[Database Migration Test] --> MigrationCheck{Migration OK?}
    MigrationCheck --> |No| Fail12[❌ Pipeline Fails]
    MigrationCheck --> |Yes| Release

    Release[Semantic Release] --> Deploy{Deploy Environment?}
    Deploy --> |Dev| DevEnv[Deploy to Dev]
    Deploy --> |Staging| StagingEnv[Deploy to Staging]
    Deploy --> |Prod| ProdEnv[Deploy to Production]

    DevEnv --> Monitor[API Monitoring & Logs]
    StagingEnv --> Monitor
    ProdEnv --> Monitor

    Monitor --> End([✅ Pipeline Complete])

    style Fail1 fill:#ff6b6b
    style Fail2 fill:#ff6b6b
    style Fail3 fill:#ff6b6b
    style Fail4 fill:#ff6b6b
    style Fail5 fill:#ff6b6b
    style Fail6 fill:#ff6b6b
    style Fail7 fill:#ff6b6b
    style Fail8 fill:#ff6b6b
    style Fail9 fill:#ff6b6b
    style Fail10 fill:#ff6b6b
    style Fail11 fill:#ff6b6b
    style Fail12 fill:#ff6b6b
    style End fill:#51cf66
    style Monitor fill:#4dabf7
```

## Pipeline Stages

### 1. Source Code Security

```yaml
# .github/workflows/nestjs-ci-cd.yml
name: NestJS DevSecOps Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

permissions:
  contents: read
  security-events: write
  pull-requests: write
  id-token: write
```

### 2. Secret Scanning

**Stage Purpose**: Prevent credential leaks and API key exposure.

```yaml
jobs:
  secret-scan:
    name: 🔐 Secret Scanning
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Gitleaks Scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: GitGuardian Scan
        uses: GitGuardian/ggshield/actions/secret@v1.33.0
        env:
          GITGUARDIAN_API_KEY: ${{ secrets.GITGUARDIAN_API_KEY }}
```

**Critical Secrets to Detect**:
- Database credentials
- JWT secrets
- OAuth client secrets
- Third-party API keys (Stripe, SendGrid, etc.)
- Redis/Cache credentials
- AWS/Azure/GCP credentials

### 3. Code Quality & Linting

**Stage Purpose**: Enforce TypeScript/JavaScript best practices and security patterns.

```yaml
  lint:
    name: 📝 Lint & Format Check
    needs: [secret-scan]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '22.x'
          cache: 'npm'

      - run: npm ci

      - name: ESLint Check
        run: npm run lint

      - name: Prettier Check
        run: npm run format:check

      - name: TypeScript Check
        run: npm run build -- --noEmit
```

**Security-Focused ESLint Configuration** (`.eslintrc.js`):
```javascript
module.exports = {
  parser: '@typescript-eslint/parser',
  parserOptions: {
    project: 'tsconfig.json',
    sourceType: 'module',
  },
  plugins: ['@typescript-eslint/eslint-plugin', 'security'],
  extends: [
    'plugin:@typescript-eslint/recommended',
    'plugin:security/recommended',
  ],
  root: true,
  env: {
    node: true,
    jest: true,
  },
  rules: {
    '@typescript-eslint/no-explicit-any': 'error',
    '@typescript-eslint/explicit-function-return-type': 'warn',
    'security/detect-object-injection': 'error',
    'security/detect-non-literal-regexp': 'error',
    'security/detect-unsafe-regex': 'error',
    'security/detect-buffer-noassert': 'error',
    'security/detect-child-process': 'warn',
    'security/detect-disable-mustache-escape': 'error',
    'security/detect-eval-with-expression': 'error',
    'security/detect-no-csrf-before-method-override': 'error',
    'security/detect-non-literal-fs-filename': 'warn',
    'security/detect-non-literal-require': 'warn',
    'security/detect-possible-timing-attacks': 'warn',
    'security/detect-pseudoRandomBytes': 'error',
  },
};
```

### 4. Static Application Security Testing (SAST)

**Stage Purpose**: Detect security vulnerabilities in source code.

```yaml
  sast:
    name: 🔍 SAST - SonarCloud
    needs: [secret-scan]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '22.x'
          cache: 'npm'

      - run: npm ci

      - name: Run Tests with Coverage
        run: npm test -- --coverage

      - name: SonarCloud Scan
        uses: sonarsource/sonarcloud-github-action@master
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

**SonarCloud Configuration** (`sonar-project.properties`):
```properties
sonar.projectKey=my-org_my-nestjs-api
sonar.organization=my-org
sonar.sources=src
sonar.tests=src
sonar.test.inclusions=**/*.spec.ts
sonar.typescript.lcov.reportPaths=coverage/lcov.info
sonar.javascript.lcov.reportPaths=coverage/lcov.info
sonar.exclusions=**/node_modules/**,**/dist/**,**/test/**,**/*.spec.ts

# Security hotspots
sonar.security.hotspots.mode=enforce

# Quality gates
sonar.qualitygate.wait=true
```

### 5. Dependency Vulnerability Scanning

**Stage Purpose**: Identify vulnerabilities in npm packages.

```yaml
  dependency-scan:
    name: 📦 Dependency Security Scan
    needs: [secret-scan]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '22.x'
          cache: 'npm'

      - run: npm ci

      - name: Snyk Security Scan
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high --fail-on=all

      - name: npm audit
        run: npm audit --audit-level=high

      - name: Generate SBOM
        run: |
          npm install -g @cyclonedx/cyclonedx-npm
          cyclonedx-npm --output-file sbom.json

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json
```

### 6. Unit Testing with Security Focus

**Stage Purpose**: Test individual components with security assertions.

```yaml
  unit-test:
    name: 🧪 Unit Tests
    needs: [lint, sast, dependency-scan]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '22.x'
          cache: 'npm'

      - run: npm ci

      - name: Run Unit Tests
        run: npm test -- --coverage --coverageReporters=json-summary

      - name: Check Coverage Threshold
        run: |
          COVERAGE=$(node -p "require('./coverage/coverage-summary.json').total.lines.pct")
          if (( $(echo "$COVERAGE < 85" | bc -l) )); then
            echo "Coverage $COVERAGE% is below 85% threshold"
            exit 1
          fi
```

**Security-Focused Unit Tests**:
```typescript
// auth.service.spec.ts
describe('AuthService', () => {
  describe('Password Hashing', () => {
    it('should hash password with bcrypt', async () => {
      const password = 'SecureP@ssw0rd';
      const hash = await authService.hashPassword(password);

      expect(hash).not.toBe(password);
      expect(hash).toMatch(/^\$2[aby]\$.{56}$/);
    });

    it('should use strong salt rounds (>= 12)', async () => {
      const hash = await authService.hashPassword('test');
      const rounds = parseInt(hash.split('$')[2]);

      expect(rounds).toBeGreaterThanOrEqual(12);
    });

    it('should prevent timing attacks in password comparison', async () => {
      const password = 'correct';
      const hash = await authService.hashPassword(password);

      const start1 = Date.now();
      await authService.comparePassword('wrong', hash);
      const time1 = Date.now() - start1;

      const start2 = Date.now();
      await authService.comparePassword('correct', hash);
      const time2 = Date.now() - start2;

      // Timing should be similar (within 50ms)
      expect(Math.abs(time1 - time2)).toBeLessThan(50);
    });
  });

  describe('JWT Tokens', () => {
    it('should generate JWT with proper claims', async () => {
      const token = await authService.generateToken({ userId: 1 });
      const decoded = jwt.decode(token);

      expect(decoded).toHaveProperty('userId');
      expect(decoded).toHaveProperty('exp');
      expect(decoded).toHaveProperty('iat');
      expect(decoded.exp - decoded.iat).toBeLessThanOrEqual(3600);
    });

    it('should reject expired tokens', async () => {
      const expiredToken = jwt.sign(
        { userId: 1 },
        'secret',
        { expiresIn: '-1h' }
      );

      await expect(authService.verifyToken(expiredToken))
        .rejects.toThrow('jwt expired');
    });

    it('should reject tampered tokens', async () => {
      const token = await authService.generateToken({ userId: 1 });
      const tamperedToken = token.slice(0, -5) + 'XXXXX';

      await expect(authService.verifyToken(tamperedToken))
        .rejects.toThrow('invalid signature');
    });
  });

  describe('SQL Injection Prevention', () => {
    it('should use parameterized queries', async () => {
      const maliciousInput = "'; DROP TABLE users; --";

      // This should not throw or execute SQL injection
      const result = await userService.findByUsername(maliciousInput);

      expect(result).toBeNull();
      // Verify users table still exists
      const usersCount = await userService.count();
      expect(usersCount).toBeGreaterThan(0);
    });
  });

  describe('XSS Prevention', () => {
    it('should sanitize user input', () => {
      const maliciousInput = '<script>alert("XSS")</script>';
      const sanitized = sanitizeService.sanitize(maliciousInput);

      expect(sanitized).not.toContain('<script>');
      expect(sanitized).not.toContain('javascript:');
    });
  });
});
```

### 7. Integration Testing

**Stage Purpose**: Test API endpoints with security scenarios.

```yaml
  integration-test:
    name: 🔗 Integration Tests
    needs: [unit-test]
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_PASSWORD: testpassword
          POSTGRES_DB: testdb
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

      redis:
        image: redis:7-alpine
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '22.x'
          cache: 'npm'

      - run: npm ci

      - name: Run Database Migrations
        run: npm run migration:run
        env:
          DATABASE_URL: postgresql://postgres:testpassword@localhost:5432/testdb

      - name: Run Integration Tests
        run: npm run test:integration
        env:
          DATABASE_URL: postgresql://postgres:testpassword@localhost:5432/testdb
          REDIS_URL: redis://localhost:6379
```

**Integration Test Examples**:
```typescript
// auth.integration.spec.ts
describe('Auth API (Integration)', () => {
  describe('POST /auth/register', () => {
    it('should prevent weak passwords', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: 'test@example.com',
          password: '12345' // Weak password
        })
        .expect(400);

      expect(response.body.message).toContain('password must be stronger');
    });

    it('should hash passwords before storing', async () => {
      const password = 'StrongP@ssw0rd!';

      await request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: 'test@example.com',
          password
        })
        .expect(201);

      const user = await userRepository.findOne({ email: 'test@example.com' });
      expect(user.password).not.toBe(password);
      expect(user.password).toMatch(/^\$2[aby]\$/);
    });

    it('should prevent duplicate registrations', async () => {
      const userData = {
        email: 'duplicate@example.com',
        password: 'SecureP@ss123'
      };

      await request(app.getHttpServer())
        .post('/auth/register')
        .send(userData)
        .expect(201);

      await request(app.getHttpServer())
        .post('/auth/register')
        .send(userData)
        .expect(409); // Conflict
    });
  });

  describe('POST /auth/login', () => {
    it('should implement rate limiting', async () => {
      const loginAttempts = Array(11).fill(null).map((_, i) =>
        request(app.getHttpServer())
          .post('/auth/login')
          .send({
            email: 'test@example.com',
            password: 'wrong'
          })
      );

      const responses = await Promise.all(loginAttempts);
      const tooManyRequests = responses.filter(r => r.status === 429);

      expect(tooManyRequests.length).toBeGreaterThan(0);
    });

    it('should not reveal user existence', async () => {
      const response1 = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'password'
        });

      const response2 = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: 'existing@example.com',
          password: 'wrongpassword'
        });

      // Both should return same generic error
      expect(response1.body.message).toBe(response2.body.message);
    });

    it('should set secure cookie flags', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: 'test@example.com',
          password: 'correct'
        })
        .expect(200);

      const cookies = response.headers['set-cookie'];
      expect(cookies[0]).toContain('HttpOnly');
      expect(cookies[0]).toContain('Secure');
      expect(cookies[0]).toContain('SameSite=Strict');
    });
  });

  describe('Authorization', () => {
    it('should reject requests without token', async () => {
      await request(app.getHttpServer())
        .get('/users/me')
        .expect(401);
    });

    it('should reject expired tokens', async () => {
      const expiredToken = generateExpiredToken();

      await request(app.getHttpServer())
        .get('/users/me')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);
    });

    it('should enforce role-based access control', async () => {
      const userToken = await loginAs('user');

      await request(app.getHttpServer())
        .delete('/admin/users/123')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(403); // Forbidden
    });
  });
});
```

### 8. API Security Testing (DAST)

**Stage Purpose**: Dynamic testing of running API for security vulnerabilities.

```yaml
  api-security-test:
    name: 🛡️ API Security Testing
    needs: [integration-test]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '22.x'
          cache: 'npm'

      - run: npm ci

      - name: Start Application
        run: |
          npm run start:prod &
          npx wait-on http://localhost:3000/health --timeout 60000
        env:
          NODE_ENV: test
          JWT_SECRET: test-secret

      - name: OWASP ZAP API Scan
        uses: zaproxy/action-api-scan@v0.7.0
        with:
          target: 'http://localhost:3000'
          format: openapi
          apikey: ${{ secrets.ZAP_API_KEY }}
          cmd_options: '-a'

      - name: Upload ZAP Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: zap-report
          path: report_html.html
```

### 9. E2E Testing

**Stage Purpose**: Test complete API workflows.

```yaml
  e2e-test:
    name: 🎯 E2E API Tests
    needs: [integration-test]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '22.x'
          cache: 'npm'

      - run: npm ci

      - name: Run E2E Tests
        run: npm run test:e2e
```

**E2E Test Examples**:
```typescript
// complete-workflow.e2e-spec.ts
describe('Complete User Workflow (E2E)', () => {
  it('should complete registration to protected resource flow', async () => {
    // 1. Register
    const registerResponse = await request(app.getHttpServer())
      .post('/auth/register')
      .send({
        email: 'e2e@example.com',
        password: 'SecureP@ss123',
        name: 'E2E User'
      })
      .expect(201);

    // 2. Verify email (mock)
    const verifyToken = registerResponse.body.verificationToken;
    await request(app.getHttpServer())
      .get(`/auth/verify?token=${verifyToken}`)
      .expect(200);

    // 3. Login
    const loginResponse = await request(app.getHttpServer())
      .post('/auth/login')
      .send({
        email: 'e2e@example.com',
        password: 'SecureP@ss123'
      })
      .expect(200);

    const accessToken = loginResponse.body.accessToken;

    // 4. Access protected resource
    const profileResponse = await request(app.getHttpServer())
      .get('/users/me')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(profileResponse.body.email).toBe('e2e@example.com');

    // 5. Update profile
    await request(app.getHttpServer())
      .patch('/users/me')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ name: 'Updated Name' })
      .expect(200);

    // 6. Refresh token
    const refreshResponse = await request(app.getHttpServer())
      .post('/auth/refresh')
      .send({ refreshToken: loginResponse.body.refreshToken })
      .expect(200);

    expect(refreshResponse.body.accessToken).toBeDefined();

    // 7. Logout
    await request(app.getHttpServer())
      .post('/auth/logout')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    // 8. Verify token is invalidated
    await request(app.getHttpServer())
      .get('/users/me')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(401);
  });
});
```

### 10. Build & Container Security

**Stage Purpose**: Create secure production builds and scan containers.

```yaml
  build-and-scan:
    name: 🐳 Build & Container Security
    needs: [e2e-test]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '22.x'
          cache: 'npm'

      - run: npm ci

      - name: Build Application
        run: npm run build

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build Docker Image
        uses: docker/build-push-action@v5
        with:
          context: .
          load: true
          tags: nestjs-app:${{ github.sha }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - name: Trivy Vulnerability Scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: nestjs-app:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

      - name: Upload Trivy Results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'

      - name: Grype Vulnerability Scan
        uses: anchore/scan-action@v3
        with:
          image: nestjs-app:${{ github.sha }}
          fail-build: true
          severity-cutoff: high
```

**Secure Dockerfile for NestJS**:
```dockerfile
# Multi-stage build
FROM node:22-alpine AS builder

# Security: Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nestjs -u 1001

WORKDIR /app

# Copy dependency files
COPY --chown=nestjs:nodejs package*.json ./

# Install dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# Copy source code
COPY --chown=nestjs:nodejs . .

# Build application
RUN npm run build

# Production stage
FROM node:22-alpine

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nestjs -u 1001

WORKDIR /app

# Copy built application and dependencies
COPY --from=builder --chown=nestjs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nestjs:nodejs /app/dist ./dist
COPY --from=builder --chown=nestjs:nodejs /app/package*.json ./

# Remove unnecessary files
RUN rm -rf /tmp/* /var/cache/apk/*

# Use non-root user
USER nestjs

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

EXPOSE 3000

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/main"]
```

### 11. Database Migration Testing

```yaml
  migration-test:
    name: 🗄️ Database Migration Test
    needs: [build-and-scan]
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_PASSWORD: testpass
          POSTGRES_DB: testdb
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
        ports:
          - 5432:5432

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '22.x'
          cache: 'npm'

      - run: npm ci

      - name: Run Migrations
        run: npm run migration:run
        env:
          DATABASE_URL: postgresql://postgres:testpass@localhost:5432/testdb

      - name: Verify Migration
        run: npm run migration:show
        env:
          DATABASE_URL: postgresql://postgres:testpass@localhost:5432/testdb

      - name: Test Rollback
        run: npm run migration:revert
        env:
          DATABASE_URL: postgresql://postgres:testpass@localhost:5432/testdb
```

### 12. Release & Deployment

```yaml
  release:
    name: 🚀 Semantic Release
    needs: [build-and-scan, migration-test]
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '22.x'
          cache: 'npm'

      - run: npm ci

      - name: Semantic Release
        uses: cycjimmy/semantic-release-action@v4
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          branches: |
            [
              'main'
            ]

  deploy:
    name: 🚢 Deploy to Production
    needs: [release]
    uses: ./.github/workflows/docker-buildx-scan-and-publish.yml
    with:
      image_name: my-nestjs-api
      tag: ${{ needs.release.outputs.new-release-version }}
    secrets:
      DOCKER_USERNAME: ${{ secrets.DOCKER_USERNAME }}
      DOCKER_PASSWORD: ${{ secrets.DOCKER_PASSWORD }}
```

## NestJS Security Best Practices

### 1. Environment Configuration

```typescript
// config/configuration.ts
import { registerAs } from '@nestjs/config';

export default registerAs('app', () => ({
  port: parseInt(process.env.PORT, 10) || 3000,
  database: {
    host: process.env.DATABASE_HOST,
    port: parseInt(process.env.DATABASE_PORT, 10) || 5432,
    username: process.env.DATABASE_USERNAME,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE_NAME,
    ssl: process.env.NODE_ENV === 'production',
  },
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: '15m',
  },
  security: {
    bcryptRounds: 12,
    rateLimitWindow: 15 * 60 * 1000, // 15 minutes
    rateLimitMax: 100,
  },
}));
```

### 2. Security Middleware & Guards

```typescript
// main.ts
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Security headers
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'https:'],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  }));

  // CORS
  app.enableCors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });

  // Rate limiting
  app.use(
    rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100,
      message: 'Too many requests from this IP',
      standardHeaders: true,
      legacyHeaders: false,
    }),
  );

  // Input validation
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // Strip unknown properties
      forbidNonWhitelisted: true, // Throw error on unknown properties
      transform: true, // Transform payloads to DTO instances
      transformOptions: {
        enableImplicitConversion: false,
      },
    }),
  );

  await app.listen(3000);
}
```

### 3. Authentication & Authorization

```typescript
// auth/jwt.strategy.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_SECRET'),
      algorithms: ['HS256'], // Specify allowed algorithms
    });
  }

  async validate(payload: any) {
    if (!payload.sub || !payload.email) {
      throw new UnauthorizedException('Invalid token payload');
    }

    return {
      userId: payload.sub,
      email: payload.email,
      roles: payload.roles || [],
    };
  }
}

// auth/roles.guard.ts
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest();
    return requiredRoles.some((role) => user.roles?.includes(role));
  }
}
```

### 4. Input Validation & Sanitization

```typescript
// DTOs with class-validator
import { IsEmail, IsString, MinLength, Matches } from 'class-validator';
import { Transform } from 'class-transformer';
import * as sanitizeHtml from 'sanitize-html';

export class CreateUserDto {
  @IsEmail()
  @Transform(({ value }) => value.toLowerCase().trim())
  email: string;

  @IsString()
  @MinLength(8)
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
    {
      message: 'Password must contain uppercase, lowercase, number and special character',
    },
  )
  password: string;

  @IsString()
  @Transform(({ value }) => sanitizeHtml(value, {
    allowedTags: [],
    allowedAttributes: {},
  }))
  name: string;
}
```

### 5. SQL Injection Prevention

```typescript
// Use TypeORM parameterized queries
@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  // ✅ SAFE: Parameterized query
  async findByEmail(email: string): Promise<User> {
    return this.userRepository.findOne({
      where: { email }, // Parameterized
    });
  }

  // ✅ SAFE: Query builder with parameters
  async searchUsers(searchTerm: string): Promise<User[]> {
    return this.userRepository
      .createQueryBuilder('user')
      .where('user.name ILIKE :searchTerm', {
        searchTerm: `%${searchTerm}%`,
      })
      .getMany();
  }

  // ❌ UNSAFE: Raw query without parameters
  async unsafeSearch(searchTerm: string): Promise<User[]> {
    // DON'T DO THIS!
    return this.userRepository.query(
      `SELECT * FROM users WHERE name LIKE '%${searchTerm}%'`
    );
  }
}
```

## Monitoring & Observability

```typescript
// logger.middleware.ts
import { Injectable, NestMiddleware, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  private logger = new Logger('HTTP');

  use(req: Request, res: Response, next: NextFunction) {
    const { method, originalUrl, ip } = req;
    const userAgent = req.get('user-agent') || '';
    const startTime = Date.now();

    res.on('finish', () => {
      const { statusCode } = res;
      const contentLength = res.get('content-length');
      const responseTime = Date.now() - startTime;

      this.logger.log(
        `${method} ${originalUrl} ${statusCode} ${contentLength} - ${userAgent} ${ip} - ${responseTime}ms`,
      );

      // Alert on suspicious activity
      if (statusCode === 401 || statusCode === 403) {
        this.logger.warn(`Unauthorized access attempt: ${ip} -> ${originalUrl}`);
      }
    });

    next();
  }
}
```

## Complete Pipeline Example

```yaml
name: NestJS Complete DevSecOps Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

permissions:
  contents: write
  security-events: write
  pull-requests: write

jobs:
  secret-scan:
    name: 🔐 Secrets
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2

  quality-checks:
    name: 📊 Quality & Security
    needs: [secret-scan]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22.x'
          cache: 'npm'
      - run: npm ci
      - run: npm run lint
      - run: npm run format:check
      - run: npm audit --audit-level=high
      - uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}

  test:
    name: 🧪 Tests
    needs: [quality-checks]
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_PASSWORD: test
        options: --health-cmd pg_isready
        ports:
          - 5432:5432
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22.x'
          cache: 'npm'
      - run: npm ci
      - run: npm test -- --coverage
      - run: npm run test:e2e

  build-scan:
    name: 🐳 Build & Scan
    needs: [test]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/build-push-action@v5
        with:
          context: .
          load: true
          tags: nestjs-api:${{ github.sha }}
      - uses: aquasecurity/trivy-action@master
        with:
          image-ref: nestjs-api:${{ github.sha }}
          exit-code: '1'
          severity: 'CRITICAL,HIGH'

  deploy:
    name: 🚀 Deploy
    needs: [build-scan]
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Deploy to production
        run: echo "Deploy to Kubernetes/ECS/etc"
```

## Conclusion

This DevSecOps pipeline ensures:
- ✅ Comprehensive API security testing
- ✅ Database security and migration safety
- ✅ Authentication/authorization verification
- ✅ Input validation and sanitization
- ✅ Container security scanning
- ✅ Continuous security monitoring
