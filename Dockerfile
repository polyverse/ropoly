FROM busybox

COPY ./polysploit /
COPY ./wwwroot/ /wwwroot
ADD ./polyverse.yml /wwwroot

CMD mkdir /tmp

EXPOSE 8080

ENTRYPOINT ["./polysploit"]
