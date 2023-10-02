.PHONY: generate
generate:
	docker build -t ebpf-builder .
	docker run --tty --rm --user "$$(id -u):$$(id -g)" --volume "$$(pwd):/ebpf-builder" ebpf-builder

.PHONY: run
run:
	go run -exec sudo .
