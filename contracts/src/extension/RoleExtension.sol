// SPDX-License-Identifier: MIT
pragma solidity >=0.8.20;

contract RoleExtension {
    // role -> did -> bool has role
    mapping(bytes32 => mapping(bytes32 => bool)) private hasRole;

    function _grantRole(
        bytes32 _role,
        bytes32 _did
    ) internal {
        hasRole[_role][_did] = true;
    }

    function _revokeRole(
        bytes32 _role,
        bytes32 _did
    ) internal {
        hasRole[_role][_did] = false;
    }

    function _hasRole(
        bytes32 _role,
        bytes32 _did
    ) internal view returns (bool){
        return hasRole[_role][_did];
    }
}
