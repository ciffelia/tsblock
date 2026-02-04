VERSION 0.8
FROM golang:1.21-bookworm
WORKDIR /go-workdir

generate:
	RUN apt-get update && \
		apt-get install -y clang llvm libbpf-dev && \
		rm -rf /var/lib/apt/lists/*

	RUN ln -s /usr/include/*/asm /usr/include/asm

	COPY . .
	RUN --mount=type=cache,target=/root/.cache/go-build \
		--mount=type=cache,target=/go/pkg/mod \
		go generate main.go

	SAVE ARTIFACT ./bpf_* AS LOCAL .

build:
	COPY . .
	RUN --mount=type=cache,target=/root/.cache/go-build \
		--mount=type=cache,target=/go/pkg/mod \
		go build

	SAVE ARTIFACT ./tsblock AS LOCAL .
