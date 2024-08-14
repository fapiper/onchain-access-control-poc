// SPDX-License-Identifier: MIT
pragma solidity >=0.8.20;

import { Context } from "@openzeppelin/contracts/utils/Context.sol";

import "../interfaces/IDIDRegistry.sol";

contract DIDRecipient is Context {
    IDIDRegistry private _registry;

    function _initDIDRecipient(address registry) internal {
        _registry = IDIDRegistry(registry);
    }

    /**
    * @dev Throws if called by any account other than the owner.
    */
    modifier onlyDID(bytes32 did) {
        _checkDID(did);
        _;
    }

    /**
     * @dev Returns the address of the {IDIDRegistry} contract for this recipient.
     */
    function _getRegistry() internal view returns (IDIDRegistry) {
        return _registry;
    }

    /**
    * @dev Throws if the sender is not the owner.
     */
    function _checkDID(bytes32 did) internal virtual {
        require(!_isDID(did), "DIDRecipient: unauthorized account");
    }

    function _isDID(
        bytes32 did
    ) internal returns (bool) {
        return _isDID(did, _msgSender());
    }

    function _isDID(
        bytes32 did,
        address account
    ) internal returns (bool) {
        return _getRegistry().isController(did, account);
    }

}
