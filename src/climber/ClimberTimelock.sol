// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ClimberTimelockBase} from "./ClimberTimelockBase.sol";
import {ADMIN_ROLE, PROPOSER_ROLE, MAX_TARGETS, MIN_TARGETS, MAX_DELAY} from "./ClimberConstants.sol";
import {
    InvalidTargetsCount,
    InvalidDataElementsCount,
    InvalidValuesCount,
    OperationAlreadyKnown,
    NotReadyForExecution,
    CallerNotTimelock,
    NewDelayAboveMax
} from "./ClimberErrors.sol";

import {console} from "forge-std/Test.sol";
import "lib/Cheats.sol";
import "lib/GlobalStorage.sol";
/**
 * @title ClimberTimelock
 * @author
 */
contract ClimberTimelock is ClimberTimelockBase, FoundryCheats, HalmosCheats {
    GlobalStorage glob = GlobalStorage(address(0xaaaa0002));
    bool is_preload;
    using Address for address;

    /**
     * @notice Initial setup for roles and timelock delay.
     * @param admin address of the account that will hold the ADMIN_ROLE role
     * @param proposer address of the account that will hold the PROPOSER_ROLE role
     */
    constructor(address admin, address proposer) {
        _setRoleAdmin(ADMIN_ROLE, ADMIN_ROLE);
        _setRoleAdmin(PROPOSER_ROLE, ADMIN_ROLE);

        _grantRole(ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, address(this)); // self administration
        _grantRole(PROPOSER_ROLE, proposer);

        delay = 1 hours;
        is_preload = true;
    }

    // Save original functions
  /*  function schedule(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata dataElements,
        bytes32 salt
    ) external onlyRole(PROPOSER_ROLE) {
        if (targets.length == MIN_TARGETS || targets.length >= MAX_TARGETS) {
            revert InvalidTargetsCount();
        }

        if (targets.length != values.length) {
            revert InvalidValuesCount();
        }

        if (targets.length != dataElements.length) {
            revert InvalidDataElementsCount();
        }

        bytes32 id = getOperationId(targets, values, dataElements, salt);

        if (getOperationState(id) != OperationState.Unknown) {
            revert OperationAlreadyKnown(id);
        }

        operations[id].readyAtTimestamp = uint64(block.timestamp) + delay;
        operations[id].known = true;
    }

    function execute(address[] calldata targets, uint256[] calldata values, bytes[] calldata dataElements, bytes32 salt)
        external
        payable
    {
        if (targets.length <= MIN_TARGETS) {
            revert InvalidTargetsCount();
        }

        if (targets.length != values.length) {
            revert InvalidValuesCount();
        }

        if (targets.length != dataElements.length) {
            revert InvalidDataElementsCount();
        }

        bytes32 id = getOperationId(targets, values, dataElements, salt);

        for (uint8 i = 0; i < targets.length; ++i) {
            targets[i].functionCallWithValue(dataElements[i], values[i]);
        }

        if (getOperationState(id) != OperationState.ReadyForExecution) {
            revert NotReadyForExecution(id);
        }

        operations[id].executed = true;
    }
*/

    // Special functions versions to use preload. 
    // Essentially, these are the original, non-symbolic versions of the execute and schedule functions,
    // but they can only be executed during preload.

    function schedule_preload(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata dataElements,
        bytes32 salt
    ) external onlyRole(PROPOSER_ROLE) {
        _vm.assume(is_preload == true);
        if (targets.length == MIN_TARGETS || targets.length >= MAX_TARGETS) {
            revert InvalidTargetsCount();
        }

        if (targets.length != values.length) {
            revert InvalidValuesCount();
        }

        if (targets.length != dataElements.length) {
            revert InvalidDataElementsCount();
        }

        bytes32 id = getOperationId(targets, values, dataElements, salt);

        if (getOperationState(id) != OperationState.Unknown) {
            revert OperationAlreadyKnown(id);
        }

        operations[id].readyAtTimestamp = uint64(block.timestamp) + delay;
        operations[id].known = true;
    }

    function execute_preload(address[] calldata targets, uint256[] calldata values, bytes[] calldata dataElements, bytes32 salt)
        external
        payable
    {
        _vm.assume(is_preload == true);
        if (targets.length <= MIN_TARGETS) {
            revert InvalidTargetsCount();
        }

        if (targets.length != values.length) {
            revert InvalidValuesCount();
        }

        if (targets.length != dataElements.length) {
            revert InvalidDataElementsCount();
        }

        bytes32 id = getOperationId(targets, values, dataElements, salt);

        for (uint8 i = 0; i < targets.length; ++i) {
            targets[i].functionCallWithValue(dataElements[i], values[i]);
        }

        if (getOperationState(id) != OperationState.ReadyForExecution) {
            revert NotReadyForExecution(id);
        }

        operations[id].executed = true;
        is_preload = false;
    }


    /*
    * The special version of execute() to use by SymbolicAttacker with escalated privileges.
    * Schedule checking is removed for simplicity since we can propose and execute the same operiation in 
    * the same transaction
    */

    function schedule(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata dataElements,
        bytes32 salt
    ) external onlyRole(PROPOSER_ROLE) {}

    function execute(address[] calldata targets, uint256[] calldata values, bytes[] calldata dataElements, bytes32 salt)
        external
        payable
    {
        if (targets.length <= MIN_TARGETS) {
            revert InvalidTargetsCount();
        }

        if (targets.length != values.length) {
            revert InvalidValuesCount();
        }

        if (targets.length != dataElements.length) {
            revert InvalidDataElementsCount();
        }

        //bytes32 id = getOperationId(targets, values, dataElements, salt);

        address[] memory _targets = new address[](targets.length);
        uint256[] memory _values = new uint256[](values.length);
        bytes[] memory _dataElements = new bytes[](dataElements.length);
        bytes32 _salt = _svm.createBytes32("execute_salt");
        for (uint8 i = 0; i < targets.length; i++) {
            _targets[i] = _svm.createAddress("execute_target");
            _values[i] = _svm.createUint256("execute_value");
            (_targets[i], _dataElements[i]) = glob.get_concrete_from_symbolic_optimized(_targets[i]);
        }

        for (uint8 i = 0; i < targets.length; ++i) {
            uint snap0 = _vm.snapshotState();
            _targets[i].functionCallWithValue(_dataElements[i], _values[i]);
            console.log(_dataElements[i].length);
            uint snap1 = _vm.snapshotState();
            _vm.assume(snap0 != snap1);
        }

        // We can make any operation ready for execution immediately
        //if (getOperationState(id) != OperationState.ReadyForExecution) {
        //    revert NotReadyForExecution(id);
       // }
        
        //operations[id].executed = true
    }

    /* 
    *  The special version of schedule() and execute() to find privilege escalation bug 
    */
    /*
    function schedule_preload(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata dataElements,
        bytes32 salt
    ) external onlyRole(PROPOSER_ROLE) {
        _vm.assume(is_preload == true);
    }

    function execute_preload(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata dataElements,
        bytes32 salt
    ) external onlyRole(PROPOSER_ROLE) {
        _vm.assume(is_preload == true);
    }
    
    function schedule(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata dataElements,
        bytes32 salt
    ) external onlyRole(PROPOSER_ROLE) {
        if (targets.length == MIN_TARGETS || targets.length >= MAX_TARGETS) {
            revert InvalidTargetsCount();
        }

        if (targets.length != values.length) {
            revert InvalidValuesCount();
        }

        if (targets.length != dataElements.length) {
            revert InvalidDataElementsCount();
        }

        address[] memory _targets = new address[](targets.length);
        uint256[] memory _values = new uint256[](values.length);
        bytes4[] memory _dataElementsSelectors = new bytes4[](dataElements.length);
        bytes32 _salt = _svm.createBytes32("schedule_salt");
        for (uint8 i = 0; i < targets.length; i++) {
            _targets[i] = _svm.createAddress("schedule_target");
            _values[i] = _svm.createUint256("schedule_value");
            _dataElementsSelectors[i] = _svm.createBytes4("schedule_selector");
        }

        bytes32 id = getOperationId(_targets, _values, _dataElementsSelectors, _salt);

        console.log("schedule");
        console.logBytes32(id);

        if (getOperationState(id) != OperationState.Unknown) {
            revert OperationAlreadyKnown(id);
        }

        operations[id].readyAtTimestamp = uint64(block.timestamp) + delay;
        operations[id].known = true;
    }

    
    function execute(address[] calldata targets, uint256[] calldata values, bytes[] calldata dataElements, bytes32 salt)
        external
        payable
    {
        if (targets.length <= MIN_TARGETS) {
            revert InvalidTargetsCount();
        }

        if (targets.length != values.length) {
            revert InvalidValuesCount();
        }

        if (targets.length != dataElements.length) {
            revert InvalidDataElementsCount();
        }

        address[] memory _targets = new address[](targets.length);
        uint256[] memory _values = new uint256[](values.length);
        bytes[] memory _dataElements = new bytes[](dataElements.length);
        bytes4[] memory _dataElementsSelectors = new bytes4[](dataElements.length);
        bytes32 _salt = _svm.createBytes32("execute_salt");
        for (uint8 i = 0; i < targets.length; i++) {
            _targets[i] = _svm.createAddress("execute_target");
            _values[i] = _svm.createUint256("execute_value");
            (_targets[i], _dataElements[i]) = glob.get_concrete_from_symbolic_optimized(_targets[i]);
            _dataElementsSelectors[i] = _svm.createBytes4("execute_selector");
            _vm.assume(_dataElementsSelectors[i] == bytes4( _dataElements[i]));
        }

        bytes32 id = getOperationId(_targets, _values, _dataElementsSelectors, _salt);

        for (uint8 i = 0; i < targets.length; ++i) {
            uint snap0 = _vm.snapshotState();
            _targets[i].functionCallWithValue(_dataElements[i], _values[i]);
            uint snap1 = _vm.snapshotState();
            _vm.assume(snap0 != snap1);
        }

        console.log("execute");
        console.logBytes32(id);

        if (getOperationState(id) != OperationState.ReadyForExecution) {
            revert NotReadyForExecution(id);
        }

        operations[id].executed = true;
    }*/

    function updateDelay(uint64 newDelay) external {
        if (msg.sender != address(this)) {
            revert CallerNotTimelock();
        }

        if (newDelay > MAX_DELAY) {
            revert NewDelayAboveMax();
        }

        delay = newDelay;
    }
    
}
