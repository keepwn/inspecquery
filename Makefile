
all: linux macos

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o inspecquery .

macos:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o inspecquery-macos .
