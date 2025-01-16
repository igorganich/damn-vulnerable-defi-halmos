// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "halmos-cheatcodes/SymTest.sol";
import "forge-std/Test.sol";
import "lib/GlobalStorage.sol";

contract SymbolicAttacker is Test, SymTest {

    //bool delegatecall_reent_guard = false;

    function handle_delegatecall() public {
        /*if (delegatecall_reent_guard) {
            revert();
        }*/
        //delegatecall_reent_guard = true;
        execute_tx("handle_delegatecall_target");
        //delegatecall_reent_guard = false;
    }

    function execute_tx(string memory target_name) private {
        GlobalStorage glob = GlobalStorage(address(0xaaaa0002));
        address target = svm.createAddress(target_name);
        bytes memory data;
        //Get some concrete target-name pair
        (target, data) = glob.get_concrete_from_symbolic_optimized(target);
        uint snap0 = vm.snapshotState();
        target.call(data);
        uint snap1 = vm.snapshotState();
        vm.assume(snap0 != snap1);
    }

	function attack() public {
        // avoid recursion
        if (msg.sender != address(0xcafe0001)) {
            revert();
        }
        execute_tx("attack_target");
        //execute_tx();
    }
}