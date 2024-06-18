FROM golang:1.22.3-alpine3.18

RUN apk add --no-cache gcompat

ARG ARCH="amd64_v1"
ARG OS="linux"
COPY dist/dyocsp_${OS}_${ARCH}/dyocsp /bin/dyocsp
COPY LICENSE /LICENSE

WORKDIR /dyocsp

EXPOSE 80
ENTRYPOINT [ "/bin/dyocsp" ]
