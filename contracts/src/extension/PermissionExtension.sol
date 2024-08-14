// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PermissionExtension {
    enum Operation {
        READ,
        WRITE
    }

    // permission id -> resources -> operations
    mapping(bytes32 => mapping(bytes32 => mapping(Operation => bool))) private permissions;

    function _registerPermissionForResource(
        bytes32 _permission,
        bytes32 _resource,
        Operation[] memory _operations
    ) internal {
        _setPermissionForResource(_permission, _resource, _operations, true);
    }

    function _unregisterPermissionForResource(
        bytes32 _permission,
        bytes32 _resource,
        Operation[] memory _operations
    ) internal {
        _setPermissionForResource(_permission, _resource, _operations, false);
    }

    function _hasPermissionToResource(
        bytes32 _permission,
        bytes32 _resource,
        Operation _operation
    ) internal view returns (bool) {
        return permissions[_permission][_resource][_operation];
    }

    function _hasAnyPermissionToResource(
        bytes32 _permission,
        bytes32 _resource,
        Operation[] memory _operations
    ) internal view returns (bool) {
        for (uint256 i = 0; i < _operations.length; i++) {
            if(_hasPermissionToResource(_permission, _resource, _operations[i])){
                return true;
            }
        }
        return false;
    }

    function _setPermissionForResource(
        bytes32 _permission,
        bytes32 _resource,
        Operation[] memory _operations,
        bool _permit
    ) private {
        for (uint256 i = 0; i < _operations.length; i++) {
            permissions[_permission][_resource][_operations[i]] = _permit;
        }
    }
}
