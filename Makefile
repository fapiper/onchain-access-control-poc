setup:
	pnpm install
	pip install -r requirements.txt

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
	sh ./use-case/01_did_registration.sh

.PHONY: setup test