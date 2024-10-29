// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "../../lib/halmos-cheatcodes/src/SymTest.sol";
import "forge-std/Test.sol";
import "../../lib/SharedGlobalData.sol";
import {WETH} from "../../src/naive-receiver/NaiveReceiverPool.sol";

contract AbstractAttacker is Test, SymTest {
    SharedGlobalData shared_data = SharedGlobalData(address(0x00000000000000000000000000000000000000000000000000000000aaaa0002)); // We can hardcode it

    function single_transaction(string memory target_id, bytes4 selector) private {
        address target = svm.createAddress(target_id);
        string memory target_name;
        (target, target_name) = shared_data.get_known_address_with_name(target);
        bytes memory data = svm.createCalldata(target_name);
        target.call(data);
        vm.assume(selector == bytes4(data));
    }

	function attack() public {
        bytes4 selector1 = svm.createBytes4("selector1");
        bytes4 selector2 = svm.createBytes4("selector2");
        single_transaction("target1", selector1);
        single_transaction("target2", selector2);
    }
}