FROM ubuntu:16.04

COPY ./polysploit /
COPY ./wwwroot/ /wwwroot
ADD ./polyverse.yml /wwwroot

CMD mkdir /tmp

ENTRYPOINT ["./polysploit"]
