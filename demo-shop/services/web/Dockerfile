# INTENTIONALLY VULNERABLE (GT-CONTAINER-003): the web front end's image, built only to be scanned (task A9).
# It holds the dependencies package-lock.json pins, so lodash 4.17.20 (GT-SCA-004 in the manifest) ships in the
# image as well. It holds the dependencies only, never web's own code (the build context below admits only the
# manifest and its lockfile): this image is never pushed, run or deployed (infra/k8s/web.yaml names a
# placeholder digest). `make container-seed-images` builds it to scan it.
#
# - The base is pinned by digest (the tag is only a label): a tag moved upstream cannot change what is built.
# - `npm ci` installs exactly package-lock.json, each package checked against its sha512 `integrity`, and runs no
#   install script (`--ignore-scripts`).
# - The final stage runs no RUN, and as UID 10001.
# - No `# syntax=` line: the builder's own Dockerfile frontend, never one pulled from a registry at build time.
# - The build context is the allow-list in Dockerfile.dockerignore: the manifest and its lockfile, never the
#   seeded .npmrc and its fake token (GT-SECRET-002), which npm would otherwise read.
ARG NODE=node:22.23.5-trixie-slim@sha256:68c76cfad89921b927eae28ba21407475e29d0ce450afcdbe70c1532db042b64

FROM ${NODE} AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

FROM ${NODE}
WORKDIR /app
COPY --from=dependencies /app/node_modules/ ./node_modules/
COPY package.json package-lock.json ./
USER 10001:10001
