# Spring Security OAuth2.0 Implementation

This repository demonstrates multiple implementations of OAuth2.0 workflows using Spring Boot and Spring Security 6.*, with distinct branches catering to specific use cases. Each branch contains a standalone example showcasing modern authentication and authorization mechanisms.

---

## Branches Overview

### 1. `main`
Comprehensive implementation of the entire OAuth2.0 workflow with the latest Spring Security and Spring Boot features.

#### Features:
- **3 Modules:**
  - **Authorization Server**: Handles user authentication and issues access tokens.
  - **Client Service**: Acts as the client application making secure API calls.
  - **Resource Server**: Protects resources and validates access tokens.
- Fully adheres to OAuth2.0 standards for secure authentication and authorization.

---

### 2. `oauth2-pkce-flow`
Implements an **OAuth2.0 Authorization Code flow with PKCE (Proof Key for Code Exchange)** for enhanced security, especially in public clients.

#### Features:
- **PKCE Support**: Secures public clients by preventing interception attacks.
- **Refresh Token Support**: Allows clients to request new access tokens without re-authenticating.
- **Form Login**: Simple login form for demonstration purposes.

---

### 3. `custom-auth-server`
A self-managed OAuth2.0 Authorization Server with extended customization capabilities.

#### Features:
- **JWT Support**: Issues JSON Web Tokens (JWT) for secure and stateless communication.
- **Flows Supported**:
  - User Registration
  - Sign-in
  - Logout
  - Refresh Token
- Easily extendable for advanced use cases.

---

### 4. `auth-service-with-otp`
A minimalistic authentication service supporting OTP-based authentication.

#### Features:
- **User Management**: Includes user registration and management.
- **OTP Authentication**: Provides one-time password (OTP) support for secure login workflows.

---

## How to Get Started

1. **Clone the Repository**:
   ```bash
   git clone <repo-url>
   cd <repo-directory>
   ```
2. **Switch to Desired Branch**:
   ```bash
   git checkout <branch-name>
   ```
3. **Build and Run the Application**:
   - Use Maven to build the project:
     ```bash
     mvn clean install
     ```
   - Run the application:
     ```bash
     mvn spring-boot:run
     ```

---

## Prerequisites
- **Java**: JDK 17+
- **Maven**: 3.8+
- **Spring Boot**: 3.*
- **Spring Security**: 6.*

---

