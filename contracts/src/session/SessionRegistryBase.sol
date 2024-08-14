// SPDX-License-Identifier: MIT
pragma solidity >=0.8.20;

import "../interfaces/IContextHandler.sol";
import "../context/ContextHandlerRecipient.sol";
import "../did/DIDRecipient.sol";

contract SessionRegistryBase is DIDRecipient {

    struct SessionInfo {
        bytes32 id;
        bytes token;
        bytes32 user;
        uint256 expiration;
        bool exists;
    }

    mapping(bytes32 => SessionInfo) private _sessions;

    constructor(
        address didRegistry
    ) {
        _initDIDRecipient(didRegistry);
    }

    function _setSession(
        bytes32 _id,
        bytes memory _token,
        bytes32 _user,
        uint256 duration
    ) internal {
        _sessions[_id] = SessionInfo({
            id: _id,
            token: _token,
            user: _user,
            exists: true,
            expiration: block.timestamp + duration
        });
    }

    function _getSession(
        bytes32 _id
    ) internal view returns (SessionInfo memory) {
        return _sessions[_id];
    }

    function _deleteSession(
        bytes32 _id
    ) internal {
        delete _sessions[_id];
    }

    function _checkSessionUser(
        bytes32 _id
    ) internal returns (bool) {
        return _isDID(_sessions[_id].user);
    }

    function _checkSessionForUser(
        bytes32 _id,
        bytes32 _user
    ) internal view returns (bool) {
        return _user == _sessions[_id].user;
    }

    function _checkSessionExists(
        bytes32 _id
    ) internal view returns (bool) {
        return _sessions[_id].exists;
    }

    function _checkSessionValid(
        bytes32 _id
    ) internal view returns (bool) {
        return _sessions[_id].expiration >= block.timestamp;
    }
}
