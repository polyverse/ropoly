FROM golang:1.11

RUN apt update -y && apt upgrade -y && apt install -y mingw-w64
