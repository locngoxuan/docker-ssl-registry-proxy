FROM alpine:3.13.5

LABEL maintainer="xuanloc0511@gmail.com"

RUN mkdir -p /app
ADD ssl /app/ssl
ADD sslproxy /app/sslproxy
WORKDIR /app

ENTRYPOINT [ "/app/sslproxy" ]