# syntax=docker/dockerfile:1

FROM maven:3.9-eclipse-temurin-21 AS build
# Contexto do build = RAIZ do repositório (docker-compose.yml), para incluir a biblioteca compartilhada de eventos.
WORKDIR /build
COPY libs/socialflux-events/pom.xml libs/socialflux-events/pom.xml
COPY libs/socialflux-events/src libs/socialflux-events/src
RUN mvn -q -B -f libs/socialflux-events/pom.xml -DskipTests install
COPY authentication_service/pom.xml authentication_service/pom.xml
RUN mvn -q -B -f authentication_service/pom.xml dependency:go-offline
COPY authentication_service/src authentication_service/src
RUN mvn -q -B -f authentication_service/pom.xml -DskipTests package

FROM eclipse-temurin:21-jre-alpine AS runner
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=build /build/authentication_service/target/authentication-service-*.jar app.jar
USER app

# Logs em JSON no stdout (um objeto por linha): é o que o Alloy lê e envia ao Loki. No terminal do host fica texto legível.
ENV LOGGING_STRUCTURED_FORMAT_CONSOLE=logstash

EXPOSE 8081
HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
  CMD wget -qO- http://localhost:8081/actuator/health >/dev/null || exit 1
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "app.jar"]
