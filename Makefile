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

run:
	pnpm node

evaluate:
	sh ./evaluate/run.sh

.PHONY: setup evaluate