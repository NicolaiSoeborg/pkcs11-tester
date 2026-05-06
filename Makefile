.PHONY: build mips32

build:
	go build -mod=vendor ./...

mips32:
	docker build -f Dockerfile.mips32 -t mips32-build .
	docker cp $$(docker create --rm mips32-build):/out/pkcs11-tester-mips32 pkcs11-tester-mips32
