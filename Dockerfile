FROM golang:1.21-bookworm AS ebpf-builder

RUN apt-get update && \
    apt-get install -y clang llvm libbpf-dev && \
    rm -rf /var/lib/apt/lists/*

RUN ln -s /usr/include/*/asm /usr/include/asm

ENV BPF2GO_CFLAGS -I/usr/include/*/asm

WORKDIR /ebpf-builder

COPY go.mod go.sum ./
RUN go mod download && \
    go mod verify && \
    rm -rf *

ENTRYPOINT go mod download && go mod verify && go generate ./...
