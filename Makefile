
all: local

docker-build-release:
	@if [ -z "$(tag)" ]; then \
		echo "Error: tag is required. Usage: make docker-build-release tag=<tag>"; \
		exit 1; \
	fi
	docker buildx build --platform linux/arm/v7,linux/arm64,linux/amd64 -t fosrl/newt:latest -f Dockerfile --push .
	docker buildx build --platform linux/arm/v7,linux/arm64,linux/amd64 -t fosrl/newt:$(tag) -f Dockerfile --push .

local: 
	CGO_ENABLED=0 go build -o ./bin/newt

go-build-release:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/newt_linux_arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -o bin/newt_linux_arm32
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -o bin/newt_linux_arm32v6
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/newt_linux_amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=riscv64 go build -o bin/newt_linux_riscv64
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o bin/newt_darwin_arm64
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o bin/newt_darwin_amd64
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/newt_windows_amd64.exe
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -o bin/newt_freebsd_amd64
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64 go build -o bin/newt_freebsd_arm64