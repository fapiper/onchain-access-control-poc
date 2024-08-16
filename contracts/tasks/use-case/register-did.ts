import { task } from "hardhat/config"
import { didEip155String } from "@/contracts/utils"
import { SimpleDIDRegistry } from "@/typechain-types"

task("register-did", "Register an account's DID")
	.addParam<string>("accountName", "The name of the account from your hardhat config file")
	.setAction(async (taskArgs, hre) => {
		const [signer, chainId] = await Promise.all([hre.ethers.getNamedSigner(taskArgs.accountName), hre.getChainId()])
		const accountDID = didEip155String(chainId, signer.address)
		const simpleDIDRegistry = (await hre.ethers.getContract("SimpleDIDRegistry")) as SimpleDIDRegistry
		const tx = await simpleDIDRegistry.connect(signer).addController(hre.ethers.id(accountDID), signer.address)
		console.log("Transaction sent")
		await tx.wait()
		console.log("Transaction confirmed: registered did", accountDID, "for address", signer.address)
	})
