# INTENTIONALLY VULNERABLE (GT-CONTAINER-004, GT-CONTAINER-005): the report worker's image, built only to be
# scanned (task A9). It holds the runtime classpath pom.xml declares, so log4j-core 2.14.1 (Log4Shell) and
# spring-beans 5.3.17 (Spring4Shell), GT-SCA-006 and GT-SCA-007 in the manifest, ship in the image as jars.
# The worker has no code of its own: this image is never pushed, run or deployed (infra/k8s/ deploys no report
# worker). `make container-seed-images` builds it to scan it.
#
# - The bases are pinned by digest (the tag is only a label): a tag moved upstream cannot change what is built.
#   At this digest, `mvn -v` is Apache Maven 3.10.0 on Temurin 21 (checked on 17 November).
# - Maven resolves the classpath with a pinned plugin and checks each download against Maven Central's
#   checksum (`--strict-checksums`); then every jar must have the SHA-256 jars.sha256 pins, and no other jar may
#   be there. A dependency of the day fails the build.
# - The final stage runs no RUN, and as UID 10001.
# - No `# syntax=` line: the builder's own Dockerfile frontend, never one pulled from a registry at build time.
# - The build context is the allow-list in Dockerfile.dockerignore: the build file and the jar pins.
ARG MAVEN=maven:3-eclipse-temurin-21@sha256:851ccd76d49d5646915645e5fb51e9b00ef53ad3dc68b0e9a2a9846b9c56bde3
ARG JRE=eclipse-temurin:21.0.13_9-jre-noble@sha256:0d57a8e90c2bb844c5a8e1b2b71e11eff06dad7edcfd803cd21ed4ae203b2515

FROM ${MAVEN} AS dependencies
WORKDIR /build
COPY pom.xml jars.sha256 ./
RUN mvn --batch-mode --no-transfer-progress --strict-checksums \
        org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies \
        -DincludeScope=runtime -DoutputDirectory=/build/lib \
    && sha256sum --check --strict jars.sha256 \
    && test "$(find lib -type f | wc -l)" -eq "$(wc -l < jars.sha256)"

FROM ${JRE}
WORKDIR /app
COPY --from=dependencies /build/lib/ ./lib/
USER 10001:10001
