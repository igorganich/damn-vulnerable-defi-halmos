// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import "lib/GlobalStorage.sol";

abstract contract Multicall is Context, Test, SymTest {

    GlobalStorage glob = GlobalStorage(address(0xaaaa0002));

    // save original function
    /*function multicall(bytes[] calldata data) external virtual returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            results[i] = Address.functionDelegateCall(address(this), data[i]);
        }
        return results;
    }*/

    // symbolic multicall
    function multicall() external virtual returns (bytes[] memory results) {
        results = new bytes[](1);
        address target = address(this);
        bytes memory newdata = svm.createCalldata("NaiveReceiverPool");
        bytes4 selector = svm.createBytes4("selector");
        vm.assume (bytes4(newdata) == selector);
        // avoid recursion
        vm.assume (selector != this.multicall.selector);
        results[0] = Address.functionDelegateCall(target, newdata);
        return results;
    }
}
