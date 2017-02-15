FROM busybox

COPY ./ropoly /

EXPOSE 8008

ENTRYPOINT ["./ropoly"]
