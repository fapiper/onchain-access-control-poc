import { simpleDeploy } from "@/contracts/utils/simpleDeploy"
import didRegistryConfig from "@/contracts/deploy/001_Deploy_SimpleDIDRegistry"

export default simpleDeploy("AccessContextHandler", async function (hre) {
	const didRegistry = await hre.deployments.get(didRegistryConfig.id ?? "").then((d) => d.address)

	return { args: [didRegistry] }
})
