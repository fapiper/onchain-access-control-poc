import { task } from "hardhat/config"
import { didEip155Hash, didEip155String, localSignerAndChainId } from "@/contracts/utils"
import { SimpleDIDRegistry } from "@/typechain-types"
import { getSimpleDIDRegistry } from "@/contracts/utils/contracts"

task("register-did", "Register an account's DID")
	.addParam<string>("accountName", "The name of the account from your hardhat config file")
	.setAction(async (taskArgs, hre) => {
		const [signer, chainId] = await localSignerAndChainId(hre, taskArgs.accountName)
		const accountDID = didEip155String(chainId, signer.address)
		const accountDIDHash = didEip155Hash(chainId, signer.address)
		const simpleDIDRegistry = await getSimpleDIDRegistry(hre, signer)
		const tx = await simpleDIDRegistry.addController(accountDIDHash, signer.address)
		console.log("Transaction sent")
		await tx.wait()
		console.log("Transaction confirmed: registered", accountDID, "for address", signer.address)
	})
