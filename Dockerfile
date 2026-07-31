FROM golang:1.26.5-alpine

RUN apk add --no-cache gcompat \
    && addgroup -S dyocsp \
    && adduser -S -G dyocsp dyocsp

ARG ARCH="amd64_v1"
ARG OS="linux"
COPY dist/dyocsp_${OS}_${ARCH}/dyocsp /bin/dyocsp
COPY LICENSE /LICENSE

WORKDIR /dyocsp

EXPOSE 80
USER dyocsp
ENTRYPOINT [ "/bin/dyocsp" ]
