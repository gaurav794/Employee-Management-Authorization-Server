#
# Build stage
#
FROM maven:3.9.1-jdk-8 AS build
COPY . .
#
# Package stage
#
FROM openjdk:8
COPY --from=build /target/*.jar demo.jar
# ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["java","-jar","demo.jar"]
