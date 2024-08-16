import { deployments } from "hardhat"
import { HardhatRuntimeEnvironment } from "hardhat/types"

export function withSnapshot<T, O>(
	tags: string | string[] = [],
	func: (hre: HardhatRuntimeEnvironment, options?: O) => Promise<T> = async () => {
		return <T>{}
	}
): (options?: O) => Promise<T> {
	return deployments.createFixture(async (hre: HardhatRuntimeEnvironment, options?: O) => {
		await deployments.fixture(tags, {
			fallbackToGlobal: true,
			keepExistingDeployments: false,
		})
		return func(hre, options)
	})
}
