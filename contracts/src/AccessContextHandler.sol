// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "./interfaces/IContextHandler.sol";
import "./context/ContextHandlerBase.sol";
import "./session/SessionRecipient.sol";
import "./interfaces/IPolicyVerifier.sol";
import "./AccessContext.sol";

contract AccessContextHandler is IContextHandler, SessionRecipient, ContextHandlerBase {

    constructor(
        address didRegistry
    ) ContextHandlerBase(didRegistry) SessionRecipient(address(0)) {
        _setInstanceImpl(address(new AccessContext()));
    }

    function createContextInstance(
        bytes32 _id,
        bytes20 _salt,
        bytes32 _did
    ) external {
        require(_checkContextIsEmpty(_id), "Access context already exists");
        address _instance = _createContextInstance(_salt, _did, _id);
        _setContextInstance(_id, _instance);
        emit CreateContextInstance(_instance);
    }

    function setSessionRegistry(
        address sessionRegistry
    ) external {
        _setSessionRegistry(sessionRegistry);
    }

    function startSession(
        bytes32 _roleContext,
        bytes32 _role,
        bytes32 _did,
        bytes32[] memory _policyContexts,
        bytes32[] memory _policies,
        IPolicyVerifier.Proof[] memory _proofs,
        uint[20][] memory _inputs,
        bytes32 _tokenId,
        bytes memory _token
    ) external {
        _forwardGrantRole(_roleContext, _role, _did, _policyContexts, _policies,_proofs,_inputs);
        _forwardStartSession(_tokenId, _token, _did);
    }

    function startSession(
        bytes32 _did,
        bytes32 _tokenId,
        bytes memory _token
    ) external {
        _forwardStartSession(_tokenId, _token, _did);
    }

    function grantRole(
        bytes32 _roleContext,
        bytes32 _role,
        bytes32 _did,
        bytes32[] memory _policyContexts,
        bytes32[] memory _policies,
        IPolicyVerifier.Proof[] memory _proofs,
        uint[20][] memory _inputs
    ) external {
        _forwardGrantRole(_roleContext, _role, _did, _policyContexts, _policies, _proofs, _inputs);
    }

    function isSession(
        bytes32 _id,
        bytes32 _did
    ) external returns (bool) {
        return _forwardIsSession(_id, _did);
    }

    function isSession(
        bytes32 _id,
        bytes32 _did,
        bytes32 _roleContext,
        bytes32 _role
    ) external returns (bool) {
        return _forwardIsSession(_id, _did) && _forwardHasRole(_roleContext, _role, _did);
    }

    function deleteContextInstance(
        bytes32 _id,
        bytes32 _did
    ) onlyContextAdmin(_id, _did) external {
        _setContextInstance(_id, address(0));
    }

    function getContextInstance(bytes32 _id) external view returns (IContextInstance) {
        return _getContextInstance(_id);
    }
}