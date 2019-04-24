FROM golang:1.12-alpine as builder

ARG VERSION=master
ARG GOOS=linux

WORKDIR /vault-admin/
COPY . .

RUN CGO_ENABLED=0 GOOS=${GOOS} go build -mod=vendor -ldflags "-X main.version=${VERSION}" -v -a -o vadmin .

CMD ["/bin/sh", "-c", "vadmin"]

# Stage 2

FROM alpine:latest

RUN apk --no-cache add ca-certificates

ENV CONFIGURATION_PATH=/config

COPY --from=builder /vault-admin/vadmin /usr/bin

ENTRYPOINT ["vadmin"]
