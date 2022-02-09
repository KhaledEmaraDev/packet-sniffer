# Packet Sniffer and DoS Attack Defender

## How to Run

1. Install Dependencies 

```
sudo apt-get install libpcap-dev libnftables-dev
```

2. Compile

```
g++ -Wall -Wextra sniffer.cpp syn_attack.cpp -o sniffer -lpcap -lpthread
```

3. Build Docker Image

```
docker build -t nft-blocker:0.1.0 .
```

4. Create Docker Network

```
docker network create nft-block
```

5. Run

```
docker run --privileged -d --name nft-blocker --network nft-block nft-blocker:0.1.0
```

6. Attack

```
docker run -it --rm --network nft-block busybox:1.34.1-musl ping nft-blocker
```

7. Watch Logs

```
docker logs -f nft-blocker
```

8. Stop

```
docker stop -t 0 nft-blocker
```

9. Remove Container

```
docker rm -f nft-blocker
```

10. Rinse and Repeat :)

## Bugs

The program doesn't respond to SIGINT. That's why it has to terminated forcefully.
