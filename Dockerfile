FROM gcc:11.2.0-bullseye

WORKDIR /usr/local/bin

RUN apt-get update && \
  apt-get install -y libpcap0.8 libpcap0.8-dev nftables && \
  rm -rf /var/lib/apt/lists/*

COPY sniffer.cpp syn_attack.h syn_attack.cpp ./

RUN g++ -Wall -Wextra -o sniffer -lpcap -lpthread sniffer.cpp syn_attack.cpp

CMD [ "sniffer" ]
