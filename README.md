# GoLang REST API with Clean Architecture & Security

> A production-grade, enterprise-oriented REST API built with Golang, emphasizing Clean Architecture, robust security, observability, and maintainability.

## 🚀 Features

*   **Clean Architecture**: Adheres to the principles of Robert C. Martin's Clean Architecture for separation of concerns, testability, and independence from frameworks.
*   **JWT Authentication & Refresh Tokens**: Secure user authentication using short-lived JWT access tokens and longer-lived refresh tokens for seamless session management.
*   **Role-Based Access Control (RBAC)**: Fine-grained control over API endpoints based on user roles (e.g., `user`, `admin`).
*   **CSRF Protection**: Mitigates Cross-Site Request Forgery attacks using Synchronizer Token Pattern, with support for both in-memory and Redis backends.
*   **Rate Limiting**: Protects against DoS and brute-force attacks with configurable rate limits per IP and route, leveraging Redis.
*   **Comprehensive Security Headers**: Implements security best practices like HSTS, CSP, X-Frame-Options, etc.
*   **Observability**:
    *   **Structured Logging**: Context-aware logging using `zap` for debugging and monitoring.
    *   **Audit Logging**: Tracks sensitive security and administrative actions.
    *   **Prometheus Metrics**: Exposes various application and database metrics for monitoring and alerting.
*   **Database**: Uses `sqlc` for type-safe SQL queries against MariaDB/MySQL, with proper connection pooling and health checks.
*   **Configuration Management**: Flexible configuration via environment variables using `viper`.
*   **Input Validation**: Server-side validation using `validator` to ensure data integrity.
*   **Testing**: Includes unit and integration tests with `testify` and `sqlmock`.
*   **CI/CD Ready**: Includes a GitHub Actions workflow for automated testing.

## ⚙️ Prerequisites

*   **Go**: Version 1.25 or later.
*   **MariaDB/MySQL**: A running database server.
*   **Redis (Optional)**: For production-grade CSRF protection and Rate Limiting.
*   **Docker & Docker Compose (Optional)**: For local setup using the provided `docker-compose.yml`.

## 🛠️ Installation & Setup

### 1. Clone the Repository


### 2. Environment Variables

Create a `.env` file in the root directory by copying the example:


Edit `.env` to configure your database, Redis (if used), JWT secrets, and other settings. **Important**: Ensure `JWT_ACCESS_SECRET` and `JWT_REFRESH_SECRET` are strong, randomly generated strings of at least 32 characters.

### 3. Database Setup

*   Ensure your MariaDB/MySQL server is running.
*   Create the database specified by `DB_NAME` in your `.env`.
*   Run the migration scripts located in the `migrations/` directory manually, or use a migration tool.

### 4. Dependencies


### 5. Run the Application

Using Go directly:


Using Make (if available):


The API server will start on the port defined by `SERVER_PORT` (default: 8080).

## 🧪 Running Tests

To run the project's tests:


## 📡 API Endpoints

The API follows RESTful conventions and is versioned under `/api/v1/`.

### Authentication

*   `POST /api/v1/auth/register` - Register a new user (role forced to 'user').
*   `POST /api/v1/auth/login` - Authenticate and receive access/refresh tokens.
*   `POST /api/v1/auth/refresh` - Refresh the access token using a valid refresh token.
*   `POST /api/v1/auth/logout` - Logout and revoke the current refresh token.

### Users (Requires Authentication)

*   `GET /api/v1/users` - List users (Admin only).
*   `GET /api/v1/users/:id` - Get a specific user (Admin only, or User accessing own data).
*   `POST /api/v1/users` - Create a new user (Admin only).
*   `PUT /api/v1/users/:id` - Update a specific user (Admin only, or User updating own profile).
*   `DELETE /api/v1/users/:id` - Delete a specific user (Admin only).
*   `PUT /api/v1/users/:id/password` - Change a user's password (Admin only, or User changing own password).

### Metrics

*   `GET /api/v1/metrics` - Prometheus metrics endpoint (if enabled via config).

## 🔐 Security

*   **JWT**: Access tokens are short-lived. Refresh tokens are stored in an HTTP-only, Secure cookie and are rotated on each use.
*   **CSRF**: Implemented for state-changing requests using a token passed in a custom header (`X-CSRF-Token`).
*   **Rate Limiting**: Configurable limits per IP and route.
*   **Input Validation**: Request bodies are validated against struct tags.
*   **Password Security**: Uses `bcrypt` with configurable cost. Includes strength checks.
*   **Secure Headers**: Automatically applied to responses.

## 📊 Observability

*   **Logging**: Structured JSON logs are output, including `request_id`, `user_id`, and caller information for easier debugging.
*   **Audit Logging**: Security-related events (logins, failed attempts, admin actions) are logged separately.
*   **Metrics**: Exposes metrics for HTTP requests, database connections, and query performance.

## 🐳 Docker (Optional)

If a `docker-compose.yml` exists (as referenced in the CI config), you can run the application and its dependencies (MariaDB, Redis) using Docker.


Ensure your `.env` file is configured to connect to the services defined in `docker-compose.yml`.

## 🤝 Contributing

1.  Fork the repository.
2.  Create a feature branch (`git checkout -b feature/AmazingFeature`).
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4.  Push to the branch (`git push origin feature/AmazingFeature`).
5.  Open a Pull Request.

## 📄 License

This project is licensed under the [MIT License](LICENSE). (Assuming MIT based on common practice, update if different).

## 📞 Support

For support, please open an issue in the GitHub repository.