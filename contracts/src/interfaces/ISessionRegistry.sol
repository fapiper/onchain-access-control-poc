// SPDX-License-Identifier: MIT
pragma solidity >=0.8.20;

interface ISessionRegistry {
    function setContextHandler(address _contextHandler) external;
    function startSession(bytes32 _id, bytes memory _token, bytes32 _did) external;
    function revokeSession(bytes32 _id) external;
    function isSessionValid(bytes32 _id) external returns (bool);
    function isSession(bytes32 _id, bytes32 _user) external returns (bool);
}
