// SPDX-License-Identifier: MIT
pragma solidity >=0.8.20;

import { Context } from "@openzeppelin/contracts/utils/Context.sol";

import "../interfaces/ISessionRegistry.sol";

contract SessionRecipient is Context {
    ISessionRegistry private sessionRegistry_;

    constructor (address sessionRegistry) {
        _setSessionRegistry(sessionRegistry);
    }

    modifier onlySessionRegistry() {
        _checkSessionRegistry();
        _;
    }

    function _getSessionRegistry() internal view returns (ISessionRegistry) {
        return sessionRegistry_;
    }

    function _setSessionRegistry(
        address _sessionRegistry
    ) internal {
        sessionRegistry_ = ISessionRegistry(_sessionRegistry);
    }

    function _checkSessionRegistry() internal view {
        require(address(_getSessionRegistry()) == _msgSender(), "SessionRecipient: unauthorized account");
    }

    function _forwardStartSession(
        bytes32 _tokenId,
        bytes memory _token,
        bytes32 _did
    ) internal {
        _getSessionRegistry().startSession(_tokenId, _token, _did);
    }

    function _forwardIsSession(
        bytes32 _tokenId,
        bytes32 _did
    ) internal returns (bool) {
       return _getSessionRegistry().isSession(_tokenId, _did);
    }
}
