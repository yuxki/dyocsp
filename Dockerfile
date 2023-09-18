FROM golang:1.20.7-alpine3.18

RUN apk add gcompat

ARG ARCH="amd64_v1"
ARG OS="linux"
COPY dist/dyocsp_${OS}_${ARCH}/dyocsp /bin/dyocsp
COPY LICENSE /LICENSE

WORKDIR /dyocsp

EXPOSE 80
ENTRYPOINT [ "/bin/dyocsp" ]
