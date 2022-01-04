FROM alpine:3.15.0

WORKDIR /usr/local/bin

RUN apk add --no-cache gcompat libpcap

COPY sniffer sniffer

CMD [ "sniffer" ]
