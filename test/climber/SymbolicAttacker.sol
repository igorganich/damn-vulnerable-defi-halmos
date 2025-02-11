// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "halmos-cheatcodes/SymTest.sol";
import "forge-std/Test.sol";
import "lib/GlobalStorage.sol";

contract SymbolicAttacker is Test, SymTest {
    // We can hardcode this address for convenience
    GlobalStorage glob = GlobalStorage(address(0xaaaa0002));
    bool reent_guard = false;

    fallback() external payable {
        vm.assume(reent_guard == false);
        reent_guard = true;
        console.log("inside fallback");
        bytes4 selector = svm.createBytes4("fallback_selector");
        vm.assume(selector == bytes4(msg.data));
        execute_tx("fallback_target");
        bytes memory retdata = svm.createBytes(1000, "fallback_retdata");// something should be returned
        reent_guard = false;
        assembly {
            return(add(retdata, 0x20), mload(retdata))
        }
    }

    function execute_tx(string memory target_name) private {
        address target = svm.createAddress(target_name);
        bytes memory data;
        //Get some concrete target-name pair
        (target, data) = glob.get_concrete_from_symbolic_optimized(target);
        target.call(data);
    }

    function attack() public {
        vm.assume(msg.sender == address(0xcafe0001)); // Only player can execute it
        execute_tx("attack_target");
    }
}