FROM golang:1.10.2-alpine as builder

ARG VERSION
ARG GOOS

RUN apk update && apk --no-cache add curl git

RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh

WORKDIR /go/src/github.com/readytalk/vault-admin/
COPY src/ .

RUN dep init

RUN CGO_ENABLED=0 GOOS=${GOOS} go build -ldflags "-X main.version=${VERSION}" -v -a -o vadmin .

CMD ["/bin/sh", "-c", "vadmin"]

# Stage 2

FROM alpine:latest

RUN apk --no-cache add ca-certificates

ENV CONFIGURATION_PATH=/config

COPY --from=builder /go/src/github.com/readytalk/vault-admin/ /usr/bin

CMD ["vadmin"]
