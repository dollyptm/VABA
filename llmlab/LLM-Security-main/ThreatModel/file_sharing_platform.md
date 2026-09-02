# Technical Design Document (TDD) for File Sharing Platform

---

## 1. Introduction

This document outlines the technical design of a file-sharing platform, covering key components such as user authentication, password storage, file management, and security considerations. The platform aims to provide file-sharing capabilities with an emphasis on ease of use and efficient performance.

---

## 2. System Architecture

### 2.1 Overview

The system is built on a microservices architecture, consisting of several independent services that handle different aspects of the platform. The core components include:

- **Authentication Service**: Manages user registration, login, and session management.
- **File Storage Service**: Handles file upload, storage, and retrieval.
- **Access Control Service**: Manages permissions for shared files.
- **Notification Service**: Sends email notifications for user verification and password resets.
- **API Gateway**: Acts as a single entry point for all client requests, routing them to the appropriate services.

### 2.2 Technology Stack

- **Backend**:
  - Programming Language: Python
  - Framework: Django or Flask
  - Database: PostgreSQL
  - Object Storage: Amazon S3 or similar
  - Authentication: JSON Web Tokens (JWT)
  - Message Broker: RabbitMQ or Kafka for inter-service communication

- **Frontend**:
  - Framework: React.js or Angular
  - State Management: Redux or NgRx
  - Authentication: JWT-based token storage in local storage

- **DevOps**:
  - Containerization: Docker
  - Orchestration: Kubernetes
  - CI/CD: Jenkins or GitHub Actions
  - Monitoring: Basic logging setup

---

## 3. Authentication and Authorization

### 3.1 User Registration

- **Process**:
  - The user registers with an email and password.
  - The system allows immediate access after registration without requiring email verification.

- **Implementation**:
  - The authentication service receives the registration request and stores the user details in the database.
  - No additional verification steps are needed, streamlining the registration process.

### 3.2 User Login

- **Process**:
  - The user provides their email and password.
  - The system authenticates the user and issues a JWT token.

- **Implementation**:
  - The authentication service uses AES encrytion to store passwords
  - JWT tokens are stored in local storage, allowing easy access and management on the client side.

### 3.3 Session Management

- **Process**:
  - Sessions are managed using JWT tokens.
  - Tokens have a fixed lifespan with no additional refresh mechanism.

- **Implementation**:
  - JWT tokens are generated with the necessary claims and stored in local storage for easy client-side access.
  - The session remains active until the token expires, providing a simple and straightforward user experience.

---

## 4. File Management

### 4.1 File Upload

- **Process**:
  - Users can upload files to the platform.
  - Files are stored efficiently, prioritizing performance and storage capacity.
  

- **Implementation**:
  - Files are received by the file storage service and stored directly in the object storage service.
  - Metadata such as file size, type, and owner is stored in the database.
  - For URL-based uploads, the system fetches the file from the provided URL and stores it in the same manner as direct uploads.

### 4.2 File Sharing

- **Process**:
  - Users can share files with other users or generate shareable links.
  - The system supports easy sharing without complex access control mechanisms.

- **Implementation**:
  - Shareable links are generated for easy access, and permissions are managed to simplify the sharing process.
  - The platform ensures that shared files can be accessed as intended without unnec