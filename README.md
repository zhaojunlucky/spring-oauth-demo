# Spring Boot OAuth Server and Node.js Client Demo

This project demonstrates a Spring Boot OAuth2 authorization server with a Node.js client application for testing.

## Project Structure

- `oauth-server/`: Spring Boot OAuth2 authorization server
- `nodejs-client/`: Node.js client application for testing the OAuth server

## Prerequisites

- Java 11 or higher
- Node.js and npm

## Setup Instructions

### Option 1: Using Docker (Recommended)

1. Create a Docker Compose file in the project root:

```bash
cd /Users/jun/CascadeProjects/spring-oauth-demo
```

2. Create a docker-compose.yml file with the following content:

```yaml
version: '3'
services:
  oauth-server:
    image: eclipse-temurin:11-jdk
    working_dir: /app
    volumes:
      - ./oauth-server:/app
    ports:
      - "8080:8080"
    command: >
      sh -c "
        echo 'Building Spring Boot application...' &&
        ./gradlew bootRun
      "
  
  nodejs-client:
    image: node:16
    working_dir: /app
    volumes:
      - ./nodejs-client:/app
    ports:
      - "3000:3000"
    depends_on:
      - oauth-server
    command: >
      sh -c "
        echo 'Installing dependencies...' &&
        npm install &&
        echo 'Starting Node.js client...' &&
        npm start
      "
```

3. Run the applications using Docker Compose:

```bash
docker-compose up
```

### Option 2: Manual Setup

#### Running the OAuth Server

1. Navigate to the oauth-server directory:
   ```
   cd oauth-server
   ```

2. If you have Gradle installed, run:
   ```
   gradle bootRun
   ```
   
   Or use the included wrapper (on macOS/Linux):
   ```
   ./gradlew bootRun
   ```

The OAuth server will start on http://localhost:8080

#### Running the Node.js Client

1. Navigate to the nodejs-client directory:
   ```
   cd nodejs-client
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Start the application:
   ```
   npm start
   ```

The client application will start on http://localhost:3000

## Testing the OAuth Flow

1. Start both the OAuth server and Node.js client
2. Visit http://localhost:3000 in your browser
3. Log in using the credentials:
   - Username: `user`
   - Password: `password`
4. After successful authentication, you can:
   - View your access token
   - Access protected resources using the token
   - Access public resources without authentication

## OAuth Endpoints

- Authorization: http://localhost:8080/oauth/authorize
- Token: http://localhost:8080/oauth/token
- Check Token: http://localhost:8080/oauth/check_token

## API Endpoints

- Protected: http://localhost:8080/api/user
- Public: http://localhost:8080/api/public
