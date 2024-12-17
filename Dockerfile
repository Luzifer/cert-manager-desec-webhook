FROM golang:1.23-alpine3.21 AS build

ENV CGO_ENABLED=0

COPY . /workspace
WORKDIR /workspace

RUN set -ex \
 && apk add --no-cache \
      git \
 && go build -o webhook -ldflags '-w -extldflags "-static"' .


FROM alpine:3.21

RUN apk add --no-cache ca-certificates

COPY --from=build /workspace/webhook /usr/local/bin/webhook

ENTRYPOINT ["webhook"]
