# Packet Sniffer and DoS Attack Defender

## How to Run

1. Install Dependencies 

```
sudo apt-get install libpcap-dev
```

2. Compile

```
g++ -Wall -Wextra sniffer.cpp syn_attack.cpp -o sniffer -lpcap -lpthread
```

3. Build Docker Image

```
docker build -t sniffer:0.1.0 .
```

4. Create Docker Network

```
docker network create sniffer
```

5. Run

```
docker run -d --name sniffer --network sniffer sniffer:0.1.0
```

6. Attack

```
docker run -it --rm --network sniffer busybox:1.34.1-musl ping sniffer
```

7. Watch Logs

```
docker logs sniffer
```

8. Stop

```
docker stop -t 0 sniffer
```

9. Remove Container

```
docker rm -f sniffer
```

10. Rinse and Repeat :)

## Bugs

The program doesn't respond to SIGINT. That's why it has to terminated forcefully.
