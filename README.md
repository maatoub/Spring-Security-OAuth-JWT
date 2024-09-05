# JWT Spring Security Demo

## About
This is a demo for API using JWT (JSON Web Token) with Spring Security and Spring Boot.

## Requirements
  - Java 17
  - Maven
## Usage
- Just start the application with the Spring Boot maven plugin (mvn spring-boot:run). The application is running at http://localhost:9999
- You can use the H2-Console for exploring the database under http://localhost:9999/h2-console
- There are three user accounts present to demonstrate the different levels of access to the endpoints in the API and the different authorization exceptions:
```bash
Username  |  Password  |  Role
Nasser    |   1234     |  ROLE_ADMIN & ROLE_USER
Ahmed     |   1234     |  ROLE_USER
```
