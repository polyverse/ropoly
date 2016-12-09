FROM busybox

COPY ./polysploit /
COPY ./wwwroot/ /wwwroot
ADD ./polyverse.yml /wwwroot

CMD mkdir /tmp

ENTRYPOINT ["./polysploit"]
