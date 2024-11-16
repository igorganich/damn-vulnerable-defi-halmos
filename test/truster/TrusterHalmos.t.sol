// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {TrusterLenderPool} from "../../src/truster/TrusterLenderPool.sol";
import "./SymbolicAttacker.sol";
import "lib/GlobalStorage.sol";

contract TrusterChallenge is Test {
    address deployer = address(0xcafe0000);
    address player = address(0xcafe0001);
    address recovery = address(0xcafe0002);
    
    uint256 constant TOKENS_IN_POOL = 1_000_000e18;

    GlobalStorage public glob; // Add global storage contract
    DamnValuableToken public token;
    TrusterLenderPool public pool;

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
        startHoax(deployer);

        // Deploy global storage. It'll have a "0xaaaa0002" address
        glob = new GlobalStorage(); 
        token = new DamnValuableToken();

        // Deploy pool and fund it
        pool = new TrusterLenderPool(token);
        token.transfer(address(pool), TOKENS_IN_POOL);

        glob.add_addr_name_pair(address(token), "DamnValuableToken");
        glob.add_addr_name_pair(address(pool), "TrusterLenderPool");
        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        assertEq(address(pool.token()), address(token));
        assertEq(token.balanceOf(address(pool)), TOKENS_IN_POOL);
        assertEq(token.balanceOf(player), 0);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function check_truster() public checkSolvedByPlayer {
        SymbolicAttacker attacker = new SymbolicAttacker();
        console.log("glob\t", address(glob));
        console.log("token\t", address(token));
        console.log("pool\t", address(pool));
        console.log("attacker\t", address(attacker));
        attacker.attack();
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Player must have executed a single transaction

        // All rescued funds sent to recovery account
        assert(token.balanceOf(address(pool)) != 0 || token.balanceOf(recovery) != TOKENS_IN_POOL);
    }
}
