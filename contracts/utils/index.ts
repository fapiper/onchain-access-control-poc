import { BigNumberish, ethers } from "ethers"
import { BytesLike } from "ethers/src.ts/utils/data"

export * from "./did"
export * from "./deploy"

const genRandHash = () => ethers.id(ethers.randomBytes(32).toString())
export const genSalt = () => ethers.randomBytes(20)

export const roleHash = (roleName: string) => ethers.id(roleName)

export const policyId = () => genRandHash()
export const permissionId = () => genRandHash()
export const resourceHash = (user: string, resource: string) => ethers.id(`${user};${resource}`)
export const operations = (ops: Array<number>) => ops.map((op) => ethers.getUint(op))
