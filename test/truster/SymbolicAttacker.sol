// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "halmos-cheatcodes/SymTest.sol";
import "forge-std/Test.sol";
import "lib/GlobalStorage.sol";

contract SymbolicAttacker is Test, SymTest {
    // We can hardcode this address for convenience
    GlobalStorage glob = GlobalStorage(address(0xaaaa0002)); 

    function execute_tx() private {
        address target = svm.createAddress("target");
        string memory name;
        //Get some concrete target-name pair
        (target, name) = glob.get_concrete_from_symbolic(target);
        bytes memory data = svm.createCalldata(name);
        target.call(data);
    }

	function attack() public {
        execute_tx();
        execute_tx();
    }
}