import { task } from "hardhat/config"
import { deploy } from "@/contracts/utils"
import * as fs from "node:fs"
import * as path from "node:path"

task("deploy-pdp", "Deploy a generic pdp")
	.addParam<string>("sourcePath", "A path to the contract")
	.addParam<string>("targetName", "The contract name")
	.setAction(async (taskArgs, hre) => {
		await hre.run("compile")
		await deploy(taskArgs.targetName, {
			contract: `${taskArgs.sourcePath}:Verifier`,
			skipIfAlreadyDeployed: false,
		})(hre)
	})
