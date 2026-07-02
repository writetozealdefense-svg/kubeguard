# KubeGuard dashboard web (static SPA). Multi-stage: build with Node, serve with
# nginx-unprivileged (non-root, minimal). distroless has no static-file server,
# so the static tier uses the hardened unprivileged nginx image.
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
# Ship the server block as a template, not a baked conf. nginx.conf carries a
# ${BFF_HOST} placeholder; the base image's entrypoint runs envsubst over
# /etc/nginx/templates/*.template into /etc/nginx/conf.d/ at start, writing the
# result as the unprivileged runtime user. Baking it directly into conf.d makes
# the file root-owned, so that envsubst step then fails with EACCES under the
# non-root user. BFF_HOST defaults to the compose/Helm service name.
ENV BFF_HOST=api:8080
COPY nginx.conf /etc/nginx/templates/default.conf.template
EXPOSE 8080
