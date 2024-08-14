import { simpleDeploy } from "@/contracts/utils/simpleDeploy"

export default simpleDeploy("SimpleDIDRegistry", async function (hre) {
	const { deployer } = await hre.getNamedAccounts()
	const chainId = await hre.getChainId()
	const initialDIDs = {
		[hre.ethers.id(`did:pkh:eip155:${chainId}:${deployer}`)]: deployer,
	}
	return {
		args: [Object.keys(initialDIDs), Object.values(initialDIDs)],
	}
})
