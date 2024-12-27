import { task } from "hardhat/config"
import { deploy } from "@/contracts/utils"
import * as fs from "node:fs"
import * as path from "node:path"

const policiesPath = path.join(__dirname, "../../src", "policies")

task("create-policy", "Create a new access policy")
	.addParam<string>("policyFile", "A path to the policy verifier contract")
	.addParam<string>("contractName", "The name of the policy deployment")
	.setAction(async (taskArgs, hre) => {
		const file = path.parse(taskArgs.policyFile)
		const contractName = taskArgs.contractName ?? file.name
		const target = path.join(policiesPath, file.base)
		await fs.promises.copyFile(taskArgs.policyFile, target)
		await hre.run("compile")
		await deploy(contractName)(hre)

		console.log("Transaction confirmed: created policy", taskArgs.contractName)
	})
