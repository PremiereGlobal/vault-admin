FROM alpine:latest

RUN apk --no-cache add ca-certificates

ENV CONFIGURATION_PATH=/config

COPY /bin/vadmin-linux /usr/bin/vadmin

ENTRYPOINT ["vadmin"]
