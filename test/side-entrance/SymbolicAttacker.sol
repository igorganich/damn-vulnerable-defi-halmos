// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "halmos-cheatcodes/SymTest.sol";
import "forge-std/Test.sol";
import "lib/GlobalStorage.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract SymbolicAttacker is Test, SymTest {
    // We can hardcode this address for convenience
    GlobalStorage glob = GlobalStorage(address(0xaaaa0002));
    bool receive_reent_guard = false;
    bool execute_reent_guard = false;

    receive() external payable {
        if (receive_reent_guard) {
            revert();
        }
        receive_reent_guard = true;
        uint256 ETH_val = svm.createUint256("ETH_val_receive");
        address target = svm.createAddress("target_receive");
        bytes memory data;
        //Get some concrete target-name pair
        (target, data) = glob.get_concrete_from_symbolic(target);
        target.call{value: ETH_val}(data);
        receive_reent_guard = false;
    }

    function execute () external payable {
        if (execute_reent_guard) {
            revert();
        }
        execute_reent_guard = true;
        uint256 ETH_val = svm.createUint256("ETH_val_execute");
        address target = svm.createAddress("target_execute");
        bytes memory data;
        //Get some concrete target-name pair
        (target, data) = glob.get_concrete_from_symbolic(target);
        target.call{value: ETH_val}(data);
        execute_reent_guard = false;
    }

    function execute_tx() private {
        uint256 ETH_val = svm.createUint256("ETH_val");
        address target = svm.createAddress("target");
        bytes memory data;
        //Get some concrete target-name pair
        (target, data) = glob.get_concrete_from_symbolic(target);
        target.call{value: ETH_val}(data);
    }

	function attack() public {
        execute_tx();
        execute_tx();
    }
}