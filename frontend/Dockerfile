FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:1.27.5-alpine
COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY validate-runtime-env.sh /docker-entrypoint.d/15-validate-mineguard-env.sh
COPY --from=build /app/dist /usr/share/nginx/html
RUN rm -f /etc/nginx/conf.d/default.conf \
    && chmod 0555 /docker-entrypoint.d/15-validate-mineguard-env.sh \
    && nginx -t
EXPOSE 80
