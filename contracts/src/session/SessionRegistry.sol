// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "../session/SessionRegistryBase.sol";
import "../interfaces/ISessionRegistry.sol";
import "../context/ContextHandlerRecipient.sol";

contract SessionRegistry is ISessionRegistry, SessionRegistryBase, ContextHandlerRecipient {

    constructor(
        address contextHandler,
        address didRegistry
    ) SessionRegistryBase(didRegistry) {
        _initContextHandlerRecipient(contextHandler);
    }

    modifier onlyUserOrContextHandler(bytes32 id){
        require(_checkSessionUser(id) || _checkContextHandler());
        _;
    }

    function setContextHandler(
        address contextHandler
    ) external {
        require(_checkContextHandler(), "not allowed");
        _setContextHandler(contextHandler);
    }

    function startSession(
        bytes32 _id,
        bytes memory _token,
        bytes32 _user
    ) override external {
        require(!_checkSessionExists(_id), "session already exists");
        _setSession(_id, _token, _user, 1 days);
    }

    function revokeSession(bytes32 _id) onlyUserOrContextHandler(_id) external {
        require(_checkSessionExists(_id), "session not found");
        _deleteSession(_id);
    }

    function isSessionValid(bytes32 _id) external view returns (bool) {
        return _checkSessionValid(_id);
    }

    function isSession(bytes32 _id, bytes32 _user) external view returns (bool) {
        return _checkSessionExists(_id) && _checkSessionValid(_id) && _checkSessionForUser(_id, _user);
    }
}