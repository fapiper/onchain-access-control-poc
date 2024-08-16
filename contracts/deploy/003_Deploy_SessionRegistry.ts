import { deploy } from "@/contracts/utils"
import didRegistryConfig from "@/contracts/deploy/001_Deploy_SimpleDIDRegistry"
import contextHandlerConfig from "@/contracts/deploy/002_AccessContextHandler"

export default deploy("SessionRegistry", async function (hre) {
	const contextHandler = await hre.deployments.get(contextHandlerConfig.id ?? "").then((d) => d.address)
	const didRegistry = await hre.deployments.get(didRegistryConfig.id ?? "").then((d) => d.address)

	return { args: [contextHandler, didRegistry] }
})
