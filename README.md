# HandyHub Auth Service

A comprehensive authentication and authorization microservice built with Go, providing secure user management, session handling, and token-based authentication.

## Features

### 🔐 Authentication & Authorization
- User registration with email verification
- Secure login with JWT tokens (access + refresh tokens)
- Password reset with email verification
- Email verification system
- Session management with Redis caching
- Rate limiting for login attempts
- Multi-device session support

### 🛡️ Security Features
- **Password Security**: Configurable password validation (length, complexity, character requirements)
- **Token Management**: JWT tokens with configurable expiration
- **Session Security**: Session cleanup, inactivity timeout, device tracking
- **Rate Limiting**: Protection against brute force attacks
- **Security Analysis**: Device change detection, IP monitoring, risk scoring

### 📊 Session Management
- Active session tracking with MongoDB + Redis
- Automatic session cleanup for expired/inactive sessions
- Session invalidation on password change
- Device information tracking (OS, browser, device type)
- IP address monitoring and geolocation support

### ⚡ Performance & Scalability
- Redis caching for active sessions and user data
- Configurable cache expiration policies
- Efficient session cleanup with batch processing
- RabbitMQ integration for async email processing

## Architecture

### Tech Stack
- **Language**: Go 1.21+
- **Framework**: Gin Web Framework
- **Database**: MongoDB (user data, sessions)
- **Cache**: Redis (active sessions, rate limiting)
- **Message Queue**: RabbitMQ (email notifications)
- **Authentication**: JWT tokens
- **Password Hashing**: Bcrypt / Argon2

### Project Structure
```
internal/
├── auth/           # Authentication service logic
├── cache/          # Redis caching service
├── config/         # Configuration management
├── email/          # Email service integration
├── logger/         # Structured logging
├── middleware/     # HTTP middleware (auth, logging, CORS)
├── models/         # Data models and DTOs
├── session/        # Session management
├── user/           # User management service
├── utils/          # Utility functions (JWT, hashing)
└── validators/     # Request validation
```

## API Endpoints

### Public Endpoints
```
POST   /auth/register                # User registration
POST   /auth/login                   # User login
POST   /auth/reset-password          # Request password reset
POST   /auth/reset-password-confirm  # Confirm password reset
GET    /auth/verify-email            # Email verification (redirect)
GET    /auth/verify-token            # Token validation
POST   /auth/refresh                 # Refresh access token
```

### Protected Endpoints (Require Authentication)
```
POST   /auth/change-password         # Change user password
POST   /auth/logout                  # User logout
```

### Health & Status
```
GET    /health                       # Basic health check
GET    /health/detailed              # Detailed health status
GET    /api/v1/status               # API status
```

## Configuration

The service uses YAML configuration with environment variable overrides:

### Key Configuration Sections

#### Database
```yaml
database:
  url: "mongodb://localhost:27017"
  dbname: "handyhub"
  user-collection: "users"
  session-collection: "sessions"
  timeout: 10
```

#### Security
```yaml
security:
  jwt-key: "your-secret-jwt-key"
  access-token-expiration: 60      # minutes
  refresh-token-expiration: 10080  # minutes (14 days)
  login-rate-limit: 5
  session-inactivity-timeout: 30
  session-cleanup-interval: 30
  password-validation:
    min-length: 6
    require-uppercase: true
    require-lowercase: true
    require-number: true
    require-special: false
    max-char-repeats: 5
    max-sequential-chars: 5
```

#### Cache & Performance
```yaml
cache:
  expiration-minutes: 60
  session-expiration-minutes: 30
  extended-expiration-minutes: 30
```

### Environment Variables
```bash
# Database
MONGODB_URL=mongodb://localhost:27017
DB_NAME=handyhub

# Redis
REDIS_URL=localhost:6379
REDIS_DB=3

# RabbitMQ
RABBITMQ_URL=amqp://guest:guest@localhost:5672/

# Security
JWT_KEY=your-super-secure-jwt-key
```

## Quick Start

### Prerequisites
- Go 1.21+
- MongoDB 4.4+
- Redis 6.0+
- RabbitMQ 3.8+

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd handyhub-auth-svc
```

2. **Install dependencies**
```bash
go mod download
```

3. **Set up configuration**
```bash
cp internal/config/cfg.yml.example internal/config/cfg.yml
# Edit cfg.yml with your settings
```

4. **Set environment variables**
```bash
export MONGODB_URL="mongodb://localhost:27017"
export REDIS_URL="localhost:6379"
export RABBITMQ_URL="amqp://guest:guest@localhost:5672/"
export JWT_KEY="your-super-secure-jwt-key"
```

5. **Run the service**
```bash
go run cmd/main.go
```

The service will start on port `:8001` by default.

## Usage Examples

### User Registration
```bash
curl -X POST http://localhost:8001/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "firstName": "John",
    "lastName": "Doe",
    "email": "john.doe@example.com",
    "password": "SecurePass123"
  }'
```

### User Login
```bash
curl -X POST http://localhost:8001/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "SecurePass123"
  }'
```

### Protected Request
```bash
curl -X POST http://localhost:8001/auth/logout \
  -H "Authorization: Bearer <access_token>"
```

### Token Refresh
```bash
curl -X POST http://localhost:8001/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "<refresh_token>"
  }'
```

## Data Models

### User Model
```go
type User struct {
    ID                  primitive.ObjectID `json:"id"`
    FirstName           string            `json:"firstName"`
    LastName            string            `json:"lastName"`
    Email               string            `json:"email"`
    Role                string            `json:"role"`
    Status              string            `json:"status"`
    IsEmailVerified     bool              `json:"isEmailVerified"`
    RegistrationDate    time.Time         `json:"registrationDate"`
    LastLoginAt         *time.Time        `json:"lastLoginAt"`
    // ... additional fields
}
```

### Session Model
```go
type Session struct {
    ID           primitive.ObjectID `json:"id"`
    SessionID    string            `json:"sessionId"`
    UserID       primitive.ObjectID `json:"userId"`
    RefreshToken string            `json:"refreshToken"`
    IPAddress    string            `json:"ipAddress"`
    UserAgent    string            `json:"userAgent"`
    CreatedAt    time.Time         `json:"createdAt"`
    ExpiresAt    time.Time         `json:"expiresAt"`
    IsActive     bool              `json:"isActive"`
    DeviceInfo   *DeviceInfo       `json:"deviceInfo"`
    // ... additional fields
}
```

## Security Features

### Password Validation
- Configurable minimum length
- Character requirements (uppercase, lowercase, numbers, special chars)
- Prevention of common passwords
- Sequential character detection
- Repeated character limits
- Keyboard pattern detection

### Session Security
- **Device Tracking**: Browser, OS, device type detection
- **Risk Analysis**: IP changes, new device detection, suspicious patterns
- **Activity Monitoring**: Last active tracking, inactivity timeouts
- **Session Cleanup**: Automatic cleanup of expired sessions

### Rate Limiting
- Login attempt limiting per email
- Configurable time windows
- Redis-based implementation
- Protection against brute force attacks

## Email Integration

The service integrates with RabbitMQ for asynchronous email processing:

### Email Types
- **Verification emails**: Sent during registration
- **Password reset emails**: Sent during password reset flow
- **Security notifications**: For suspicious activities (planned)

### Email Templates
Located in `templates/` directory:
- `verification.html`: Email verification template
- `reset-password.html`: Password reset template

## Monitoring & Logging

### Health Checks
- `/health`: Basic service health
- `/health/detailed`: Comprehensive system status including database and Redis connectivity

### Structured Logging
- JSON output support for production
- Configurable log levels
- Request/response logging middleware
- Security event logging

### Metrics (Planned)
- Authentication success/failure rates
- Session duration analytics
- Security incident tracking

## Development

### Running Tests
```bash
go test ./...
```

### Code Structure Guidelines
- **Service Layer**: Business logic implementation
- **Repository Layer**: Data access abstraction
- **Handler Layer**: HTTP request/response handling
- **Middleware**: Cross-cutting concerns (auth, logging, CORS)
- **Models**: Data structures and DTOs
- **Validators**: Input validation and sanitization

### Adding New Features
1. Define models in `internal/models/`
2. Add repository methods if needed
3. Implement service logic
4. Add HTTP handlers
5. Register routes
6. Add validation rules
7. Update documentation

## Production Deployment

### Docker Support (Recommended)
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o auth-service cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/auth-service .
CMD ["./auth-service"]
```

### Environment Configuration
- Use environment variables for sensitive data
- Configure proper connection pools
- Set up monitoring and alerting
- Enable TLS/SSL
- Configure load balancing

### Database Indexes
Ensure proper MongoDB indexes for performance:
```javascript
// Users collection
db.users.createIndex({ "email": 1 }, { unique: true })
db.users.createIndex({ "verification_token": 1 }, { sparse: true })

// Sessions collection
db.sessions.createIndex({ "session_id": 1 }, { unique: true })
db.sessions.createIndex({ "user_id": 1 })
db.sessions.createIndex({ "refresh_token": 1 }, { sparse: true })
db.sessions.createIndex({ "expires_at": 1 })
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Standards
- Follow Go conventions and best practices
- Add comprehensive tests for new features
- Update documentation for API changes
- Use structured logging
- Implement proper error handling

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:
- Create an issue in the GitHub repository
- Contact the development team
- Check the documentation and examples

---

**HandyHub Auth Service** - Secure, scalable authentication for modern applications.