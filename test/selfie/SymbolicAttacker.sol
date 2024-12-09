// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "halmos-cheatcodes/SymTest.sol";
import "forge-std/Test.sol";
import "lib/GlobalStorage.sol";
import {DamnValuableVotes} from "../../src/DamnValuableVotes.sol";

contract SymbolicAttacker is Test, SymTest {
    // We can hardcode this address for convenience
    GlobalStorage glob = GlobalStorage(address(0xaaaa0002)); 

    function onFlashLoan(address initiator, address token,
                        uint256 amount, uint256 fee,
                        bytes calldata data
    ) external returns (bytes32) 
    {
        address target = svm.createAddress("target_onFlashLoan");
        bytes memory data;
        //Get some concrete target-name pair
        (target, data) = glob.get_concrete_from_symbolic(target);
        target.call(data);
        DamnValuableVotes(token).approve(address(msg.sender), 2**256 - 1); // unlimited approve for pool
        return (keccak256("ERC3156FlashBorrower.onFlashLoan"));
    }

    function execute_tx() private {
        address target = svm.createAddress("target");
        bytes memory data;
        //Get some concrete target-name pair
        (target, data) = glob.get_concrete_from_symbolic(target);
        target.call(data);
    }

    function attack() public {
        execute_tx();
        uint256 warp = svm.createUint256("warp");
        vm.warp(block.timestamp + warp); // wait for symbolic time between transactions
        execute_tx();
        warp = svm.createUint256("warp");
        vm.warp(block.timestamp + warp); // wait for symbolic time between transactions
        //execute_tx();
    }
}