FROM busybox

COPY ./polysploit /
COPY ./wwwroot/ /wwwroot

CMD mkdir /tmp

EXPOSE 8080

ENTRYPOINT ["./polysploit"]
