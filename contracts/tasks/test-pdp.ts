import { task } from "hardhat/config"
import { Verifier } from "@/typechain-types"

task("test-pdp", "Test a generic pdp")
	.addParam<string>("targetName", "A name of the contract")
	.addParam<string>("proof", "The proof parameters")
	.setAction(async (taskArgs, hre) => {
		const signer = (await hre.ethers.getSigners())[0]
		const { inputs, proof } = JSON.parse(taskArgs.proof)
		const pdp = await hre.ethers.getContract<Verifier>(taskArgs.targetName, signer)
		const tx = await pdp.verifyTx(proof, inputs)
		const receipt = await tx.wait()
		console.log(hre.ethers.formatUnits(receipt?.gasUsed ?? 0, "wei"))
	})
