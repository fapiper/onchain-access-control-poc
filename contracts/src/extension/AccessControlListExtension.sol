// SPDX-License-Identifier: MIT
pragma solidity >=0.8.20;

contract AccessControlListExtension {

    struct Assignment {
        // count policies
        uint256 policyCount;
        // policy context -> policies -> exists
        mapping(bytes32 => mapping(bytes32 => bool)) policies;
        // permission -> exists
        mapping(bytes32 => bool) permissions;
    }

    // role context -> roles -> assignment
    mapping(bytes32 => mapping(bytes32 => Assignment)) internal assignments;

    function _assignPermissionsToRole(
        bytes32 _roleContext,
        bytes32 _role,
        bytes32[] memory _permissions
    ) internal {
        for (uint256 i = 0; i < _permissions.length; i++) {
            _assignPermissionToRole(_roleContext, _role, _permissions[i]);
        }
    }

    function _assignPermissionToRole(
        bytes32 _roleContext,
        bytes32 _role,
        bytes32 _permission
    ) internal {
        assignments[_roleContext][_role].permissions[_permission] = true;
    }

    function _unassignPermissionsToRole(
        bytes32 _roleContext,
        bytes32 _role,
        bytes32[] memory _permissions
    ) internal {
        for (uint256 i = 0; i < _permissions.length; i++) {
            _unassignPermissionToRole(_roleContext, _role, _permissions[i]);
        }
    }

    function _unassignPermissionToRole(
        bytes32 _roleContext,
        bytes32 _role,
        bytes32 _permission
    ) internal {
        assignments[_roleContext][_role].permissions[_permission] = false;
    }

    function _assignPoliciesToRole(
        bytes32 _roleContext,
        bytes32 _role,
        bytes32[] memory _policyContexts,
        bytes32[] memory _policies
    ) internal {
        for (uint256 i = 0; i < _policyContexts.length; i++) {
            _assignPolicyToRole(_roleContext, _role, _policyContexts[i], _policies[i]);
        }
    }

    function _assignPolicyToRole(
        bytes32 _roleContext,
        bytes32 _role,
        bytes32 _policyContext,
        bytes32 policy_
    ) internal {
        assignments[_roleContext][_role].policies[_policyContext][policy_] = true;
        assignments[_roleContext][_role].policyCount += 1;
    }

    function _unassignPoliciesToRole(
        bytes32 _roleContext,
        bytes32 _role,
        bytes32[] memory _policyContexts,
        bytes32[] memory _policies
    ) internal {
        for (uint256 i = 0; i < _policyContexts.length; i++) {
            _unassignPolicyToRole(_roleContext, _role, _policyContexts[i], _policies[i]);
        }
    }

    function _unassignPolicyToRole(
        bytes32 _roleContext,
        bytes32 _role,
        bytes32 _policyContext,
        bytes32 _policy
    ) internal {
        require(_getPolicyCount(_roleContext, _role) > 0, "no policy found for role");
        assignments[_roleContext][_role].policies[_policyContext][_policy] = false;
        assignments[_roleContext][_role].policyCount -= 1;
    }

    function _hasRolePolicies(
        bytes32 _roleContext,
        bytes32 _role,
        bytes32[] memory _policyContexts,
        bytes32[] memory _policies
    ) internal view returns (bool) {
        for (uint256 i = 0; i < _policies.length; i++) {
            if(!_hasRolePolicy(_roleContext, _role, _policyContexts[i], _policies[i])){
                return false;
            }
        }
        return true;
    }

    function _hasRolePolicy(
        bytes32 _roleContext,
        bytes32 _role,
        bytes32 _policyContext,
        bytes32 _policy
    ) internal view returns (bool) {
        return assignments[_roleContext][_role].policies[_policyContext][_policy];
    }

    function _hasRoleExpectedPolicyCount(
        bytes32 _roleContext,
        bytes32 _role,
        uint256 _expectedCount
    ) internal view returns (bool) {
        return _getPolicyCount(_roleContext, _role) == _expectedCount;
    }

    function _getPolicyCount(
        bytes32 _roleContext,
        bytes32 _role
    ) internal view returns (uint256) {
        return assignments[_roleContext][_role].policyCount;
    }

}
