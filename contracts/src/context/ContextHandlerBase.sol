// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/Clones.sol";

import "../interfaces/IContextInstance.sol";
import "../interfaces/IPolicyVerifier.sol";
import "../did/DIDRecipient.sol";

contract ContextHandlerBase is DIDRecipient {

    // The address of the base context instance implementation
    address private _instanceImpl;

    // context -> address
    mapping(bytes32 => IContextInstance) internal _contexts;

    constructor(address didRegistry) {
        _initDIDRecipient(didRegistry);
    }

    modifier onlyContextAdmin(
        bytes32 _context,
        bytes32 _did
    ){
        require((_checkContextAdmin(_context, _did)), "not allowed");
        _;
    }

    function _checkContextAdmin(
        bytes32 _context,
        bytes32 _did
    ) internal returns (bool) {
        return _getContextInstance(_context).checkAdmin(_did, _msgSender());
    }

    function _checkContextIsEmpty(
        bytes32 _context
    ) internal view returns (bool) {
        return address(_contexts[_context]) == address(0);
    }

    function _forwardGrantRole(
        bytes32 _roleContext,
        bytes32 _role,
        bytes32 _did,
        bytes32[] memory _policyContexts,
        bytes32[] memory _policies,
        IPolicyVerifier.Proof[] memory _proofs,
        uint[20][] memory _inputs
    ) internal {
        _getContextInstance(_roleContext).grantRole(_role, _did, _policyContexts, _policies, _proofs, _inputs);
    }

    function _forwardHasRole(
        bytes32 _roleContext,
        bytes32 _role,
        bytes32 _did
    ) internal returns (bool) {
        return _getContextInstance(_roleContext).hasRole(_role, _did);
    }

    function _createContextInstance(
        bytes20 _salt,
        bytes32 _owner,
        bytes32 _id
    ) internal returns (address _instance) {
        bytes32 hash = _hashContext(_salt, _owner, _id, address(this), address(_getRegistry()));
        IContextInstance clone = IContextInstance(Clones.cloneDeterministic(_instanceImpl, hash));
        clone.init(_owner, _id, address(this), address(_getRegistry()));
        return address(clone);
    }

    function _setContextInstance(
        bytes32 _id,
        address _ctx
    ) internal {
        _contexts[_id] = IContextInstance(_ctx);
    }

    function _getContextInstance(
        bytes32 _id
    ) internal view returns (IContextInstance) {
        return _contexts[_id];
    }

    function _setInstanceImpl(
        address _newInstanceImpl
    ) internal {
        _instanceImpl = _newInstanceImpl;
    }

    function _getInstanceImpl() internal view returns (address) {
        return _instanceImpl;
    }

    function _hashContext(
        bytes20 _salt,
        bytes32 _owner,
        bytes32 _contextId,
        address _contextHandler,
        address _didRegistry
    ) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(keccak256(abi.encodePacked(_owner, _contextId, _contextHandler, _didRegistry)), _salt));
    }

}
