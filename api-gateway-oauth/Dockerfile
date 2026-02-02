# Этап сборки
FROM eclipse-temurin:17 AS builder
WORKDIR /app
COPY . .
RUN ./gradlew clean bootJar --no-daemon

# Этап запуска
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=builder /app/build/libs/api-gateway-oauth-*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]