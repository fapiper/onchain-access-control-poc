import hre from "hardhat"
import { expect } from "chai"
import { localDidEip155 } from "@/contracts/utils"
import { withSnapshot } from "@/contracts/test/utils"
import { SimpleDIDRegistry } from "@/typechain-types"

const setupTest = withSnapshot(["SimpleDIDRegistry"], async (hre) => {
	const { resourceOwner, resourceUser, accreditationBody } = await hre.ethers.getNamedSigners()

	const instance = (await hre.ethers.getContract("SimpleDIDRegistry")) as SimpleDIDRegistry

	return {
		instance,
		resourceOwner,
		resourceUser,
		accreditationBody,
	}
})

describe("SimpleDIDRegistry.addController", () => {
	context("When a user registers its DID with valid parameters", () => {
		it("should successfully register the DID with the current sender as a controller", async () => {
			const { instance, resourceOwner } = await setupTest()
			const resourceOwnerDidHash = await localDidEip155(hre, "resourceOwner").then(hre.ethers.id)
			expect(instance.connect(resourceOwner).addController(resourceOwnerDidHash, resourceOwner.address)).to.not
				.reverted
		})
	})
})
