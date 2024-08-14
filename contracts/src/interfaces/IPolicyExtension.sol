// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IPolicyVerifier.sol";

interface IPolicyExtension {

    struct Policy {
        bytes32 context;
        bytes32 id;
        IPolicyVerifier verifier;
        bool exists;
    }
}
