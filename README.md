# Packet Sniffer and DoS Attack Defender

## How to Run

1. Compile

```
gcc -Wall -Wextra -lpcap sniffer.c -o sniffer
```

2. Build Docker Image

```
docker build -t sniffer:0.1.0 .
```

3. Create Docker Network

```
docker network create sniffer
```

4. Run

```
docker run -d --name sniffer --network sniffer sniffer:0.1.0
```

5. Attack

```
docker run -it --rm --network sniffer busybox:1.34.1-musl ping sniffer
```

6. Watch Logs

```
docker logs sniffer
```

7. Stop

```
docker stop -t 0 sniffer
```

8. Remove Container

```
docker rm -f sniffer
```

9. Rinse and Repeat :)

## Bugs

The program doesn't respond to SIGINT. That's why it has to terminated forcefully.
