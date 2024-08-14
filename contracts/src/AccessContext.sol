// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "./did/DIDOwnable.sol";
import "./context/ContextInstance.sol";
import "./interfaces/IContextInstance.sol";
import "./interfaces/IPolicyVerifier.sol";
import "./extension/AccessControlListExtension.sol";
import "./extension/PolicyExtension.sol";
import "./extension/RoleExtension.sol";
import "./extension/PermissionExtension.sol";

contract AccessContext is IContextInstance, DIDOwnable, AccessControlListExtension, PermissionExtension, PolicyExtension, RoleExtension {

    function init(
        bytes32 initialOwner,
        bytes32 id,
        address handler,
        address didRegistry
    ) external {
        _initDIDOwnable(initialOwner, didRegistry);
        _initPolicyExtension(id, handler);
    }

    /**
     *  @notice         Allows only context admin (owner) or role member for `_role`.
     *
     *  @param _role           Uid of the role within this context.
     */
    modifier onlyOwnerOrRole(
        bytes32 _role,
        bytes32 _did
    ){
        require(_hasRole(_role, _did) || _isOwner(_did));
        _;
    }

    /**
     *  @notice         Verifies a policy and grants role.
     *  @dev            Caller must be owner or role member.
     *                  Emits {RoleGrant Event}.
     *
     *  @param _role           Uid of the role within this context.
     *  @param _did            DID of the user.
     *  @param _policyContexts Uid of policy contexts.
     *  @param _policies       Uids of the policies of context in `policyContexts` at same index.
     */
    function grantRole(
        bytes32 _role,
        bytes32 _did,
        bytes32[] memory _policyContexts,
        bytes32[] memory _policies,
        IPolicyVerifier.Proof[] memory _proofs,
        uint[20][] memory _inputs
    ) external {
        bytes32 thisContext = _thisContext();
        uint256 policyCount = _policies.length;
        for (uint256 i = 0; i < policyCount; i++) {
            Policy memory policy_ = _getPolicy(_policyContexts[i], _policies[i]);
            require(_hasRolePolicy(thisContext, _role, policy_.context, policy_.id), "policy for role not allowed");
            require(_verifyPolicy(policy_, _proofs[i], _inputs[i]), "policy not satisfied");
        }
        _grantRole(_role, _did);
    }

    /**
     *  @notice         Checks if a given did is admin.
     *
     *  @param _did         DID of the admin of this context.
     *  @param _account     Address of the DID controller.
     */
    function checkAdmin(
        bytes32 _did,
        address _account
    ) external returns (bool) {
        _checkOwner(_did, _account);
        return true;
    }

    /**
     *  @notice         Checks if a given did has a role.
     *
     *  @param _role        Role to check against
     *  @param _did         DID of the user
     */
    function hasRole(
        bytes32 _role,
        bytes32 _did
    ) external view returns (bool) {
        return _hasRole(_role, _did);
    }

    /**
     *  @notice         Revokes a role.
     *  @dev            Caller must be owner or role member.
     *                  Emits {RoleRevoke Event}.
     *
     *  @param _role           Uid of the role within this context.
     *  @param _did            DID of the admin of this context.
     */
    function revokeRole(
        bytes32 _role,
        bytes32 _did
    ) external onlyOwnerOrRole(_role, _did) {
        _revokeRole(_role, _did);
    }

    /**
     *  @notice         Sets up a role for an already registered policy by assigning it to a role, registering
     *                  permissions for a resource and assigning them to a role.
     *  @dev            Caller must have owner role.
     *                  Emits {RoleSetup Event}.
     *
     *  @param _role           Uid of the role within this context.
     *  @param _policyContext  Uid of the access context for the policy.
     *  @param _policy         Uid of the policy within `_policyContext`.
     *  @param _permission     Uid of the permission.
     *  @param _resource       Uid of the resource for which to assign permissions to.
     *  @param _operations     Permitted operations for the resource. Currently either [READ] or [READ, WRITE].
     *  @param _did            DID of the admin of this context.
     */
    function setupRole(
        bytes32 _role,
        bytes32 _policyContext,
        bytes32 _policy,
        bytes32 _permission,
        bytes32 _resource,
        Operation[] memory _operations,
        bytes32 _did
    ) external onlyOwner(_did) {
        bytes32 thisContext = _thisContext();
        _assignPolicyToRole(thisContext, _role, _policyContext, _policy);
        _registerPermissionForResource(_permission, _resource, _operations);
        _assignPermissionToRole(thisContext, _role, _permission);
    }

    /**
     *  @notice         Sets up a role by registering a policy and assigning it to a role, registering
     *                  permissions for a resource and assigning them to a role.
     *  @dev            Caller must have owner role.
     *                  Emits {RoleSetup Event}.
     *
     *  @param _role           Uid of the role within this context.
     *  @param _policy         Uid of the policy within this context.
     *  @param _permission     Uid of the permission.
     *  @param _resource       Uid of the resource for which to assign permissions to.
     *  @param _operations     Permitted operations for the resource. Currently either [READ] or [READ, WRITE].
     *  @param _verifier       Address of the policy verifier contract.
     *  @param _did            DID of the admin of this context.
     */
    function setupRole(
        bytes32 _role,
        bytes32 _policy,
        bytes32 _permission,
        bytes32 _resource,
        Operation[] memory _operations,
        address _verifier,
        bytes32 _did
    ) external onlyOwner(_did) {
        bytes32 thisContext = _thisContext();
        _registerPolicy(thisContext, _policy, _verifier);
        _assignPolicyToRole(thisContext, _role, thisContext, _policy);
        _registerPermissionForResource(_permission, _resource, _operations);
        _assignPermissionToRole(thisContext, _role, _permission);
    }

    /**
     *  @notice         Registers a policy without assigning it to a role.
     *  @dev            Caller must have owner role.
     *                  Emits {PolicyRegistered Event}.
     *
     *  @param _policy         Uid of the policy within this context.
     *  @param _verifier       Address of the policy verifier contract.
     *  @param _did            DID of the admin of this context.
     */
    function registerPolicy(
        bytes32 _policy,
        address _verifier,
        bytes32 _did
    ) external onlyOwner(_did) {
        _registerPolicy(_thisContext(), _policy, _verifier);
    }

    /**
     *  @notice         Registers a policy and assigns it to a role.
     *  @dev            Caller must have owner role.
     *                  Emits {PolicyRegistered Event}.
     *
     *  @param _policy         Uid of the policy within this context`.
     *  @param _verifier       Address of the policy verifier contract.
     *  @param _role           Uid of the role within `_roleContext`.
     *  @param _did            DID of the admin of this context.
     */
    function registerPolicy(
        bytes32 _policy,
        address _verifier,
        bytes32 _role,
        bytes32 _did
    ) external onlyOwner(_did) {
        bytes32 thisContext = _thisContext();
        _registerPolicy(thisContext, _policy, _verifier);
        _assignPolicyToRole(thisContext, _role, thisContext, _policy);
    }

    /**
     *  @notice         Get a policy from own or cross context.
     *
     *  @param _context        Uid of the policy context.
     *  @param _id             Uid of the role within `_context`.
     *
     * @return policy          The policy struct of `_context`
     */
    function getPolicy(
        bytes32 _context,
        bytes32 _id
    ) external view returns (Policy memory) {
        return _getPolicy(_context, _id);
    }

    /**
     *  @notice         Get policies from own or cross context.
     *
     *  @param _contexts        Uids of the policy contexts.
     *  @param _ids             Uids of the roles within `_contexts`.
     *
     * @return policies          The policy struct array of `_contexts`
     */
    function getPolicies(
        bytes32[] memory _contexts,
        bytes32[] memory _ids
    ) external view returns (Policy[] memory policies) {
        return _getPolicies(_contexts, _ids);
    }

    /**
     *  @notice         Assigns an existing policy from own or cross-context to a role from own context.
     *  @dev            Caller must have owner role.
     *                  Emits {PolicyAssigned Event}.
     *
     *  @param _policyContext  Uid of the access context for the policy.
     *  @param _policy         Uid of the policy within `_policyContext`.
     *  @param _role           Uid of the role within `_roleContext`.
     *  @param _did            DID of the admin of this context.
     */
    function assignPolicy(
        bytes32 _policyContext,
        bytes32 _policy,
        bytes32 _role,
        bytes32 _did
    ) external onlyOwner(_did) {
        _assignPolicyToRole(_thisContext(), _role, _policyContext, _policy);
    }

    /**
     *  @notice         Registers a new permission by assigning a resource and operations. Does not assign a role.
     *  @dev            Caller must have owner role.
     *                  Emits {PermissionRegistered Event}.
     *
     *  @param _permission     Uid of the permission.
     *  @param _resource       Uid of the resource for which to assign permissions to.
     *  @param _operations     Permitted operations for the resource. Currently either [READ] or [READ, WRITE].
     */
    function registerPermission(
        bytes32 _permission,
        bytes32 _resource,
        Operation[] memory _operations
    ) external {
        _registerPermissionForResource(_permission, _resource, _operations);
    }

    /**
     *  @notice         Registers a new permission by assigning a resource, operations and a role.
     *  @dev            Caller must have owner role.
     *                  Emits {PermissionRegistered Event}.
     *
     *  @param _permission     Uid of the permission.
     *  @param _resource       Uid of the resource for which to assign permissions to.
     *  @param _operations     Permitted operations for the resource. Currently either [READ] or [READ, WRITE].
     *  @param _roleContext    Uid of the access context for the role.
     *  @param _role           Uid of the role within `_roleContext`.
     *  @param _did            DID of the admin of this context.
     */
    function registerPermission(
        bytes32 _permission,
        bytes32 _resource,
        Operation[] memory _operations,
        bytes32 _roleContext,
        bytes32 _role,
        bytes32 _did
    ) external onlyOwner(_did) {
        _registerPermissionForResource(_permission, _resource, _operations);
        _assignPermissionToRole(_roleContext, _role, _permission);
    }

    /**
     *  @notice         Assigns an existing permission to a role.
     *  @dev            Caller must have owner role.
     *                  Emits {PermissionAssigned Event}.
     *
     *  @param _permission     Uid of the permission.
     *  @param _roleContext    Uid of the access context for the role.
     *  @param _role           Uid of the role within `_roleContext`.
     *  @param _did            DID of the admin of this context.
     */
    function assignPermission(
        bytes32 _permission,
        bytes32 _roleContext,
        bytes32 _role,
        bytes32 _did
    ) external onlyOwner(_did) {
        _assignPermissionToRole(_roleContext, _role, _permission);
    }

    /**
     *  @notice         Remove permission assignment to a role.
     *  @dev            Caller must have owner role.
     *                  Emits {PermissionUnassigned Event}.
     *
     *  @param _permission     Uid of the permission.
     *  @param _roleContext    Uid of the access context for the role.
     *  @param _role           Uid of the role within `_roleContext`.
     *  @param _did            DID of the admin of this context.
     */
    function unassignPermission(
        bytes32 _permission,
        bytes32 _roleContext,
        bytes32 _role,
        bytes32 _did
    ) external onlyOwner(_did) {
        _unassignPermissionToRole(_roleContext, _role, _permission);
    }
}