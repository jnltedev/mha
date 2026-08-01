FROM nginx:1.27-alpine

RUN apk add --no-cache tzdata

# Processed via nginx's built-in envsubst-on-templates entrypoint step at
# container start, substituting ${PORT} — only variables that actually exist
# in the container's environment get substituted, so nginx's own $host /
# $uri / $remote_addr etc. are left untouched.
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY index.html /usr/share/nginx/html/index.html
COPY compare.html /usr/share/nginx/html/compare.html
COPY view.html /usr/share/nginx/html/view.html
COPY css/ /usr/share/nginx/html/css/
COPY js/ /usr/share/nginx/html/js/

ENV PORT=3000
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:${PORT}/ >/dev/null || exit 1
