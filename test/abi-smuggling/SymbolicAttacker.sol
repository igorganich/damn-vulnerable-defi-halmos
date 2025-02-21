// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "halmos-cheatcodes/SymTest.sol";
import "forge-std/Test.sol";
import "lib/GlobalStorage.sol";

contract SymbolicAttacker is Test, SymTest {
    // We can hardcode this address for convenience
    GlobalStorage glob = GlobalStorage(address(0xaaaa0002));
    bool reent_guard = false;
    bool is_preload = false;

    fallback() external payable {
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
        //uint snap0 = vm.snapshotState();
        target.call(data);
        //uint snap1 = vm.snapshotState();
        //vm.assume(snap0 != snap1);
    }

    function attack() public {
        vm.assume(msg.sender == address(0xcafe0001)); // Only player can execute it
        //execute_tx("attack_target");
        bytes memory b = svm.createBytes(1000, "b");
        address a = svm.createAddress("a");
        a.call(b);
    }
}
