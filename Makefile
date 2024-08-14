setup:
	pnpm install

clean:
	rm -rf node_modules typechain-types artifacts cache

build:
	pnpm compile

build-clean:
	make clean
	make build

test:
	echo "TODO test"

run:
	echo "TODO run"