FROM busybox

ADD tokensd /bin/tokensd/tokensd
ADD ca-certificates.crt /etc/ssl/certs/

WORKDIR /bin/tokensd

EXPOSE 4001

CMD /bin/tokensd
