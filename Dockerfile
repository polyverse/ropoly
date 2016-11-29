FROM ubuntu:16.04

COPY ./polysploit /
COPY ./wwwroot/ /wwwroot

CMD mkdir /tmp

ENTRYPOINT ["./polysploit"]
