# How to run the current version 
```
# start server
go run ./cmd/server

# start client 1 with this(temporary method)
CHAT_ID_FILE=./id1.key go run ./cmd/client

# start client 2 with this
CHAT_ID_FILE=./id2.key go run ./cmd/client
```