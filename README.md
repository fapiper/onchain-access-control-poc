# Non-disclosing Blockchain-based Access Control for Data Sharing in Multi-Party Environments

## Hardhat Configuration

-   [Typechain](https://github.com/dethcrypto/TypeChain) plugin enabled (typescript type bindings for smart contracts)
-   [hardhat-deploy](https://github.com/wighawag/hardhat-deploy) plugin enabled
-   Testing environment configured and operational, with test coverage
-   Prettier and eslint configured for project files and solidity smart contract
-   [Solhint](https://github.com/protofire/solhint) configured for enforcing best practices
-   Github actions workflows prepared for CI/CD

Check the Hardhat documentation for more information.

https://hardhat.org/getting-started/

## Project Structure

```text
.
├── contracts
│   ├── BasicERC1155.sol
│   ├── BasicERC20.sol
│   └── BasicERC721.sol
├── deploy
│   ├── Deploy_BasicERC1155.ts
│   ├── Deploy_BasicERC20.ts
│   └── Deploy_BasicERC721.ts
├── deployments
├── hardhat.config.ts
├── tasks
│   ├── erc1155
│   ├── erc20
│   ├── erc721
│   └── utils
└── test
    ├── BasicERC1155.ts
    ├── BasicERC20.ts
    └── BasicERC721.ts
```

## Supported Networks

-   Hardhat Network (localhost)
-   Ethereum Mainnet
-   Ethereum Sepolia Testnet
-   Polygon Mainnet
-   Polygon Mumbai Testnet

Feel free to add more networks in `hardhat.config.ts` file.

## Hardhat Shorthand

We recommend installing `hh autocomplete` so you can use `hh` shorthand globally.

```shell
pnpm i -g hardhat-shorthand
```

https://hardhat.org/guides/shorthand.html

### Common Shorthand Commands

-   `hh compile` - to compile smart contract and generate typechain ts bindings
-   `hh test` - to run tests
-   `hh deploy` - to deploy to local network (see options for more)
-   `hh node` - to run a localhost node
-   `hh help` - to see all available commands
-   `hh TABTAB` - to use autocomplete

## Usage

### Setup

#### 1. Install Dependencies

```shell
pnpm install
```

#### 2. Compile Contracts

```shell
pnpm run compile
```

#### 3. Environment Setup

Create `.env` file and add your environment variables. You can use `.env.example` as a template.

If you are going to use public network, make sure you include the right RPC provider for that network.

Make sure you include either `MNEMONIC` or `PRIVATE_KEY` in your `.env` file.

### Example Flow - Deploy ERC721 Token

> This is an example flow to deploy an ERC721 token to a public network and interact with it.

#### 1. Deploy BasicERC721 Contract

```shell
hh deploy --network sepolia --tags BasicERC721
```

#### 2. Verify Contract

```shell
hh --network sepolia etherscan-verify
```

#### 3. Interact With Contract - Mint

```shell
hh erc721-mint \
 --contract 0x77337983A7D1699FaF51a5f43b9907fB7B614097 \
 --recipient 0x73faDd7E476a9Bc2dA6D1512A528366A3E50c3cF \
 --network sepolia
```

---

### Testing

#### Run Tests

```shell
pnpm run test
```

#### Run Coverage

```shell
pnpm run coverage
```

---

### Project Hygiene

#### Prettier - Non Solidity Files

```shell
pnpm run format:check
pnpm run format:write
```

#### Lint - Non Solidity Files

```shell
pnpm run lint:check
pnpm run lint:fix
```

#### Prettier - Solidity

```shell
pnpm run sol:format:check
pnpm run sol:format:write
```

#### Solhint - Enforcing styles and security best practices

```shell
pnpm run solhint
```