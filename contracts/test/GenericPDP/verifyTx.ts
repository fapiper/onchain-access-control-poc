import hre from "hardhat"
import { expect } from "chai"
import { localDidEip155 } from "@/contracts/utils"
import { withSnapshot } from "@/contracts/test/utils"
import { SimpleDIDRegistry } from "@/typechain-types"

const setupTest = withSnapshot(["GenericPDP", process.argv[4]], async (hre) => {
	const { resourceOwner, resourceUser, accreditationBody } = await hre.ethers.getNamedSigners()

	const contractName = process.argv[4]

	const instance = await hre.ethers.getContract(contractName)

	return {
		instance,
		resourceOwner,
		resourceUser,
		accreditationBody,
	}
})

describe("PDP.verifyTx", () => {
	context("When a subject passes valid parameters", () => {
		it("should successfully verify the verifiable presentation", async () => {
			console.log(process.argv)
			const { instance, resourceUser } = await setupTest()

			const proof = JSON.parse(process.argv[5])

			expect(instance.connect(resourceUser).verifyTx(proof)).to.not.reverted
		})
	})
})
