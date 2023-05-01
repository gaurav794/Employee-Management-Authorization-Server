FROM openjdk:11
ADD target/authorization-server.jar authorization-server.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","authorization-server.jar"]