FROM busybox

COPY ./tokensd /tokensd
COPY ./ca-certificates.crt /etc/ssl/certs/

EXPOSE 4001

CMD ["/tokensd"]
