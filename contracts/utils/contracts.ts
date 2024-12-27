import { AccessContext, AccessContextHandler, SimpleDIDRegistry } from "@/typechain-types"
import { HardhatRuntimeEnvironment } from "hardhat/types"
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers"

export const getContractWithSigner = (
	hre: HardhatRuntimeEnvironment,
	contractName: string,
	signer?: HardhatEthersSigner
) => hre.ethers.getContract(contractName, signer)

const getContractWithSignerAt = (
	hre: HardhatRuntimeEnvironment,
	contractName: string,
	at: string,
	signer?: HardhatEthersSigner
) => hre.ethers.getContractAt(contractName, at, signer)

export const getSimpleDIDRegistry = (hre: HardhatRuntimeEnvironment, signer?: HardhatEthersSigner) =>
	getContractWithSigner(hre, "SimpleDIDRegistry", signer) as Promise<SimpleDIDRegistry>

export const getAccessContextHandler = (hre: HardhatRuntimeEnvironment, signer?: HardhatEthersSigner) =>
	getContractWithSigner(hre, "AccessContextHandler", signer) as Promise<AccessContextHandler>

export const getAccessContextAt = (hre: HardhatRuntimeEnvironment, at: string, signer?: HardhatEthersSigner) =>
	getContractWithSignerAt(hre, "AccessContext", at, signer) as Promise<AccessContext>
