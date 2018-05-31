.PHONY: all

all:
	go build -o gen .

.PHONY: clean
clean:
	rm -f client.* server.* ca.*