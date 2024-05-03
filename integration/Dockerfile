# Docker image for testing integration, in the compose network.

FROM ubuntu:noble
RUN apt update \
  && apt install -y openssl curl unzip \
  && curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
  && unzip awscliv2.zip \
  && ./aws/install

COPY . /dyocsp
WORKDIR /dyocsp
