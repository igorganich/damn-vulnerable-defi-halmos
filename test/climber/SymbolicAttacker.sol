// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "halmos-cheatcodes/SymTest.sol";
import "forge-std/Test.sol";
import "lib/GlobalStorage.sol";

contract SymbolicAttacker is Test, SymTest {
    // We can hardcode this address for convenience
    GlobalStorage glob = GlobalStorage(address(0xaaaa0002)); 

    fallback() external payable {
        bytes4 selector = svm.createBytes4("fallback_selector");
        vm.assume(selector == bytes4(msg.data));
        execute_tx("fallback_target");
        bytes memory retdata = svm.createBytes(1000, "fallback_retdata");// something should be returned
        assembly {
            return(add(returndata, 0x20), mload(returndata));
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
        execute_tx("attack_target");
    }
}