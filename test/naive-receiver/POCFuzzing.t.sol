// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "./POCTarget.sol";
import {Test, console} from "forge-std/Test.sol";

contract POCFuzzing is Test {
    POCTarget target;
    address deployer = makeAddr("deployer");

    function setUp() public {
        startHoax(deployer);
        target = new POCTarget();
        vm.stopPrank();
        targetSender(deployer);
    }

    function invariant_isWorking() public {
        assert (target.a() != 1);
    }
}
