// SPDX-License-Identifier: MIT
pragma solidity >=0.8.20;

interface IDIDRegistry {
    struct DIDConfig {
        uint currentController;
    }

    event DIDControllerChanged(
        bytes32 identity,
        address controller
    );

    function getController(bytes32 identity) external returns (address);
    function addController(bytes32 identity, address controller) external;
    function removeController(bytes32 identity, address controller) external;
    function changeController(bytes32 identity, address newController) external;
    function isController(bytes32 identity, address actor) external returns (bool);
}
