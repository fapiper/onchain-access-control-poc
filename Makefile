setup:
	pnpm install
	pip install -r requirements.txt

clean:
	rm -rf typechain-types artifacts cache

build:
	pnpm compile

build-clean:
	make clean
	make build

test:
	echo "TODO test"

run:
	sh ./use-case/01_did_registration.sh

evaluate:
	sh ./evaluate/run.sh

.PHONY: setup test