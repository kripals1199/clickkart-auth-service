# Dockerfile
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src src
RUN mvn -B -q clean package -DskipTests

FROM eclipse-temurin:21-jre
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
RUN addgroup --system clickkart && adduser --system --ingroup clickkart clickkart
WORKDIR /app
COPY --from=build /workspace/target/clickkart-auth-service.jar app.jar
# logback-spring.xml writes to ./logs (APPLICATION/ERROR/AUDIT/SECURITY/SQL/ACCESS appenders) -
# this directory must exist and be writable by the non-root user before the JVM starts.
RUN mkdir -p /app/logs && chown -R clickkart:clickkart /app
USER clickkart

ENV SPRING_PROFILES_ACTIVE=dev
EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD curl -fsS http://localhost:${SERVER_PORT:-8081}/actuator/health | grep -q '"status":"UP"' || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]
