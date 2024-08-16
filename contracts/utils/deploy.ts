import type { DeployFunction, DeployOptions as _DeployOptions } from "hardhat-deploy/types"
import { HardhatRuntimeEnvironment } from "hardhat/types"

type DeployOptions = Omit<_DeployOptions, "from">
type DeployOptionsOrFn = ((hre: HardhatRuntimeEnvironment) => Promise<DeployOptions> | DeployOptions) | DeployOptions

export function deploy(name: string, options?: DeployOptionsOrFn) {
	const func: DeployFunction = async function (hre) {
		const deployOptions = typeof options === "function" ? await options(hre) : options

		const { getNamedAccounts, getChainId, network, deployments } = hre
		const { deployer } = await getNamedAccounts()
		console.log("deploying", name, "with account", deployer, "...")
		const chainId = await getChainId()
		const { deploy } = deployments

		if (!deployer) {
			throw new Error("No deployer available")
		}

		const contract = await deploy(name, {
			from: deployer,
			log: true,
			autoMine: true, // speed up deployment on local network (ganache, hardhat), no effect on live networks
			...deployOptions,
		})

		console.log(`${name} deployed to ${contract.address} on ${network.name} (${chainId})\n`)
	}

	func.id = name
	func.tags = [name]
	return func
}
