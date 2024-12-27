import { task } from "hardhat/config"
import {
	didEip155Hash,
	didEip155String,
	genSalt,
	localSignerAndChainId,
	operations,
	permissionId,
	policyId,
	resourceHash,
	roleHash,
} from "@/contracts/utils"
import { getAccessContextAt, getAccessContextHandler } from "@/contracts/utils/contracts"

task("register-resource", "Register a new resource")
	.addParam<string>("roleName", "The name of the role")
	.addParam<string>("accountName", "The name of the policy creator")
	.addParam<string>("policyName", "The name of the policy deployment")
	.setAction(async (taskArgs, hre) => {
		const [signer, chainId] = await localSignerAndChainId(hre, taskArgs.accountName)

		// 1. get deployed policy
		const contractName = taskArgs.policyName
		const policyDeployment = await hre.deployments.get(contractName)

		// 2. create context
		const accountDID = didEip155String(chainId, signer.address)
		const accountDIDHash = didEip155Hash(chainId, signer.address)
		const accessContextHandler = await getAccessContextHandler(hre, signer)
		const tx = await accessContextHandler.createContextInstance(accountDIDHash, genSalt(), accountDIDHash)
		await tx.wait()

		// 3. create policy
		const events = await accessContextHandler.queryFilter(accessContextHandler.filters.CreateContextInstance, -1)
		const accessContextAddress = events[0]?.args[0]
		const accessContext = await getAccessContextAt(hre, accessContextAddress, signer)
		await accessContext["setupRole(bytes32,bytes32,bytes32,bytes32,uint8[],address,bytes32)"](
			roleHash(taskArgs.roleName),
			policyId(),
			permissionId(),
			resourceHash(accountDIDHash, "a/shared/resource.example"),
			operations([1]),
			policyDeployment.address,
			accountDIDHash
		)

		console.log(
			"Transaction confirmed: register resource for role",
			taskArgs.roleName,
			"for resources of",
			accountDID
		)
	})
