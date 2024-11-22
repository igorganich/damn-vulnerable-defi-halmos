// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {SideEntranceLenderPool} from "../../src/side-entrance/SideEntranceLenderPool.sol";
import "lib/GlobalStorage.sol";
import "./SymbolicAttacker.sol";

contract SideEntranceChallenge is Test {
    address deployer = address(0xcafe0000);
    address player = address(0xcafe0001);
    address recovery = address(0xcafe0002);

    uint256 constant ETHER_IN_POOL = 1000e18;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 1e18;

    GlobalStorage glob;
    SideEntranceLenderPool pool;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    /**
     * SETS UP CHALLENGE - DO NOT TOUCH
     */
    function setUp() public {
        startHoax(deployer, 1 << 80);
        glob = new GlobalStorage();
        pool = new SideEntranceLenderPool();
        pool.deposit{value: ETHER_IN_POOL}();
        vm.deal(player, PLAYER_INITIAL_ETH_BALANCE);
        glob.add_addr_name_pair(address(pool), "SideEntranceLenderPool");
        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        assertEq(address(pool).balance, ETHER_IN_POOL);
        assertEq(player.balance, PLAYER_INITIAL_ETH_BALANCE);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function check_sideEntrance() public checkSolvedByPlayer {
        SymbolicAttacker attacker = new SymbolicAttacker();
        vm.deal(address(attacker), PLAYER_INITIAL_ETH_BALANCE);
        vm.deal(address(player), 0); // Player's ETH is transferred to attacker.
        console.log("GlobalStorage\t\t", address(glob));
        console.log("SideEntranceLenderPool\t", address(pool));
        console.log("SymbolicAttacker\t\t", address(attacker));
        attacker.attack();
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        assert(address(pool).balance >= ETHER_IN_POOL);
    }
}
