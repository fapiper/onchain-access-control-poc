// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "../interfaces/IDIDRegistry.sol";

contract SimpleDIDRegistry is IDIDRegistry {

    mapping(bytes32 => address[]) public controllers;
    mapping(bytes32 => DIDConfig) private configs;
    mapping(address => uint) public changed;

    modifier onlyController(bytes32 identity, address actor) {
        require(isController(identity, actor), 'Not authorized');
        _;
    }

    modifier onlyControllerOrNew(bytes32 identity, address actor) {
        require(controllers[identity].length <= 0 || isController(identity, actor), 'Not authorized');
        _;
    }

    constructor(bytes32[] memory _identities, address[] memory _controllers) {
        require(_identities.length == _controllers.length, "identities and controllers not equal");
        for (uint i = 0; i < _identities.length; i++) {
            addController(_identities[i], msg.sender, _controllers[i]);
        }
    }

    function getControllers(bytes32 identity) public view returns (address[] memory) {
        return controllers[identity];
    }

    function isController(bytes32 identity, address actor) override public view returns (bool) {
        return actor == getController(identity);
    }

    function getController(bytes32 identity) override public view returns (address) {
        uint len = controllers[identity].length;
        require(len > 0, "identity not found");
        if (len == 1) return controllers[identity][0];
        DIDConfig storage config = configs[identity];
        address controller = address(0);
        if( config.currentController >= len ){
            controller = controllers[identity][0];
        } else {
            controller = controllers[identity][config.currentController];
        }
        require(controller != address(0), "identity not found");
        return controller;
    }

    function setCurrentController(bytes32 identity, uint index) internal {
        configs[identity].currentController = index;
    }

    function _getControllerIndex(bytes32 identity, address controller) internal view returns (int) {
        for (uint i = 0; i < controllers[identity].length; i++) {
            if (controllers[identity][i] == controller) {
                return int(i);
            }
        }
        return - 1;
    }

    function addController(bytes32 identity, address actor, address newController) internal onlyControllerOrNew(identity, actor) {
        int controllerIndex = _getControllerIndex(identity, newController);

        if (controllerIndex < 0) {
            controllers[identity].push( newController );
        }
    }

    function removeController(bytes32 identity, address actor, address controller) internal onlyController(identity, actor) {
        require(controllers[identity].length > 1, 'You need at least two controllers to delete' );
        require(getController(identity) != controller , 'Cannot delete current controller' );
        int controllerIndex = _getControllerIndex(identity, controller);

        require( controllerIndex >= 0, 'Controller not exist' );

        uint len = controllers[identity].length;
        address lastController = controllers[identity][len - 1];
        controllers[identity][uint(controllerIndex)] = lastController;
        if( lastController == getController(identity) ){
            configs[identity].currentController = uint(controllerIndex);
        }
        delete controllers[identity][len - 1];
        controllers[identity].pop();
    }

    function changeController(bytes32 identity, address actor, address newController) internal onlyController(identity, actor) {
        int controllerIndex = _getControllerIndex(identity, newController);

        require( controllerIndex >= 0, 'Controller not exist' );

        if (controllerIndex >= 0) {
            setCurrentController(identity, uint(controllerIndex));

            emit DIDControllerChanged(identity, newController);
        }
    }

    function addController(bytes32 identity, address controller) override external {
        addController(identity, msg.sender, controller);
    }

    function removeController(bytes32 identity, address controller) override external {
        removeController(identity, msg.sender, controller);
    }

    function changeController(bytes32 identity, address newController) external override {
        changeController(identity, msg.sender, newController);
    }
}