import { HardhatRuntimeEnvironment } from "hardhat/types"

export const didEip155String = (chainId: string | number, address: string) => `did:pkh:eip155:${chainId}:${address}`

export const localDidEip155 = (hre: HardhatRuntimeEnvironment, accountName: string) =>
	Promise.all([hre.getChainId(), hre.ethers.getNamedSigner(accountName)]).then(([chainId, signer]) =>
		didEip155String(chainId, signer.address)
	)
