// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IContextHandler.sol";
import "../interfaces/IContextInstance.sol";

contract ContextHandlerRecipient {

    IContextHandler private contextHandler_;

    function _initContextHandlerRecipient(address contextHandler) internal {
        _setContextHandler(contextHandler);
    }

    function _setContextHandler(address contextHandler) internal {
        contextHandler_ = IContextHandler(contextHandler);
    }

    function _checkContextHandler() internal view returns (bool) {
        return _checkContextHandler(msg.sender);
    }

    function _checkContextHandler(address account) internal view returns (bool) {
        return address(_contextHandler()) == account;
    }

    function _contextHandler() internal view returns (IContextHandler) {
        return contextHandler_;
    }

    function _contextInstance(bytes32 context) internal view returns (IContextInstance) {
        return _contextHandler().getContextInstance(context);
    }
}
