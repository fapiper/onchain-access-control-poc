// SPDX-License-Identifier: MIT
pragma solidity >=0.8.20;

import "../context/ContextInstance.sol";
import "../interfaces/IPolicyExtension.sol";
import "../interfaces/IPolicyVerifier.sol";

interface IContextInstance is IPolicyExtension {

    function init(bytes32 initialOwner, bytes32 id, address handler, address didRegistry) external;
    function checkAdmin(bytes32 _did, address _account) external returns (bool);
    function getPolicy(bytes32 _context, bytes32 _id) external view returns (Policy memory policy);
    function getPolicies(bytes32[] memory _contexts, bytes32[] memory _ids) external view returns (Policy[] memory policies);
    function grantRole(bytes32 _role, bytes32 _did, bytes32[] memory _policyContexts, bytes32[] memory _policies, IPolicyVerifier.Proof[] memory _proofs, uint[20][] memory _inputs) external;
    function hasRole(bytes32 _role, bytes32 _did) external returns (bool);
}
