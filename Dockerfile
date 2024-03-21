ARG GO_VERSION=1.16-alpine

FROM docker.io/golang:${GO_VERSION} as build
ARG BASE_PATH
ENV BASE_PATH "v1"

WORKDIR /go/src

RUN apk update && apk add pkgconfig xmlsec-dev libxml2-dev build-base openssl-dev
RUN go get github.com/crewjam/go-xmlsec

COPY . .

RUN cd example && go get && go build -ldflags="-s -w"

WORKDIR /go/src/spidsaml

RUN go test -v

FROM docker.io/golang:${GO_VERSION}
ARG BASE_PATH
ENV BASE_PATH "v1"
RUN apk update && apk add xmlsec-dev libxml2-dev openssl-dev

RUN mkdir /usr/local/bin/spid_go
COPY --from=build /go/src/example/ /usr/local/bin/spid_go
RUN mv /usr/local/bin/spid_go/example /usr/local/bin/spid_go/spid_go 

WORKDIR /usr/local/bin/spid_go/
ENTRYPOINT ["./spid_go"]
