# Use an official OpenJDK image as a base image
FROM eclipse-temurin:17-jdk-alpine

VOLUME [ "/tmp" ]
COPY target/security-*.jar /security-auth-jwt.jar
ENTRYPOINT [ "java","-jar","security-auth-jwt.jar" ]
EXPOSE 8888