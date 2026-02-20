BINARY := peselbrute

.PHONY: build clean run

build:
	go build -ldflags="-s -w" -o $(BINARY) .

clean:
	rm -f $(BINARY)
