import { deploy, localDidEip155 } from "@/contracts/utils"

export default deploy("SimpleDIDRegistry", async function (hre) {
	const { deployer } = await hre.getNamedAccounts()
	const didHash = await localDidEip155(hre, "deployer").then(hre.ethers.id)

	return {
		args: [[didHash], [deployer]],
	}
})
