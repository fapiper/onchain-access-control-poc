// SPDX-License-Identifier: MIT
pragma solidity >=0.8.20;

import "./DIDRecipient.sol";
 
/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * The initial owner is set to the address provided by the deployer. This can
 * later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract DIDOwnable is DIDRecipient {
    bytes32 private _owner;

    /**
     * @dev The caller account is not authorized to perform an operation.
     */
    error OwnableUnauthorizedAccount(bytes32 did, address account);

    /**
     * @dev The owner is not a valid owner account. (eg. `bytes32(0)`)
     */
    error OwnableInvalidOwner(bytes32 owner);

    event OwnershipTransferred(bytes32 indexed previousOwner, bytes32 indexed newOwner);

    /**
     * @dev Initializes the contract setting the address provided by the deployer as the initial owner.
     */
    function _initDIDOwnable(bytes32 initialOwner, address didRegistry) internal {
        _initDIDRecipient(didRegistry);
        if (initialOwner == "") {
            revert OwnableInvalidOwner("");
        }
        _transferOwnership(initialOwner);
    }
    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner(bytes32 did) {
        _checkOwner(did);
        _;
    }

    /**
     * @dev Returns the did of the current owner.
     */
    function owner() public view virtual returns (bytes32) {
        return _owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner(
        bytes32 did
    ) internal virtual {
        _checkOwner(did, _msgSender());
    }

    /**
     * @dev Throws if the actor is not the owner.
     */
    function _checkOwner(
        bytes32 did,
        address account
    ) internal virtual {
        if (!_isOwner(did, account)) {
            revert OwnableUnauthorizedAccount(did, account);
        }
    }

    /**
     * @dev Returns true if the sender is the owner.
     */
    function _isOwner(
        bytes32 did
    ) internal virtual returns (bool) {
        return _isOwner(did, _msgSender());
    }

    /**
     * @dev Returns true if the account is the owner.
     */
    function _isOwner(
        bytes32 did,
        address account
    ) internal virtual returns (bool) {
        return owner() == did && _isDID(did, account);
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby disabling any functionality that is only available to the owner.
     */
    function renounceOwnership(bytes32 owner_) public virtual onlyOwner(owner_) {
        _transferOwnership("");
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(
        bytes32 oldOwner,
        bytes32 newOwner
    ) public virtual onlyOwner(oldOwner) {
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(bytes32 newOwner) internal virtual {
        bytes32 oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}
