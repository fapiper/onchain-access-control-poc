import { HardhatRuntimeEnvironment } from "hardhat/types"
import { ethers } from "ethers"

export const localSignerAndChainId = (hre: HardhatRuntimeEnvironment, accountName: string) =>
	Promise.all([hre.ethers.getNamedSigner(accountName), hre.getChainId()])

export const didEip155String = (chainId: string | number, address: string) => `did:pkh:eip155:${chainId}:${address}`

export const didEip155Hash = (chainId: string | number, address: string) => ethers.id(didEip155String(chainId, address))

export const localDidEip155 = (hre: HardhatRuntimeEnvironment, accountName: string) =>
	Promise.all([hre.getChainId(), hre.ethers.getNamedSigner(accountName)]).then(([chainId, signer]) =>
		didEip155String(chainId, signer.address)
	)
