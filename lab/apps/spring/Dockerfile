FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q dependency:go-offline
COPY src ./src
RUN mvn -q -DskipTests package
FROM eclipse-temurin:21-jre
COPY --from=build /src/target/labapp.jar /app.jar
ENV PORT=8000
EXPOSE 8000
ENTRYPOINT ["java", "-jar", "/app.jar"]
