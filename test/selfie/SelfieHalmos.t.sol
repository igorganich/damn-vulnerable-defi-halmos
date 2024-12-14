// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {DamnValuableVotes} from "../../src/DamnValuableVotes.sol";
import {SimpleGovernance} from "../../src/selfie/SimpleGovernance.sol";
import {SelfiePool} from "../../src/selfie/SelfiePool.sol";
import "lib/GlobalStorage.sol";
import "./SymbolicAttacker.sol";
import "halmos-cheatcodes/SymTest.sol";

contract SelfieChallenge is Test, SymTest {
    address deployer = address(0xcafe0000);
    address player = address(0xcafe0001);
    address recovery = address(0xcafe0002);

    uint256 constant TOKEN_INITIAL_SUPPLY = 2_000_000e18;
    uint256 constant TOKENS_IN_POOL = 1_500_000e18;

    GlobalStorage glob;
    DamnValuableVotes token;
    SimpleGovernance governance;
    SelfiePool pool;

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

        glob = new GlobalStorage();

        // Deploy token
        token = new DamnValuableVotes(TOKEN_INITIAL_SUPPLY);

        // Deploy governance contract
        governance = new SimpleGovernance(token);

        // Deploy pool
        pool = new SelfiePool(token, governance);

        // Fund the pool
        token.transfer(address(pool), TOKENS_IN_POOL);

        glob.add_addr_name_pair(address(token), "DamnValuableVotes");
        glob.add_addr_name_pair(address(governance), "SimpleGovernance");
        glob.add_addr_name_pair(address(pool), "SelfiePool");

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        assertEq(address(pool.token()), address(token));
        assertEq(address(pool.governance()), address(governance));
        assertEq(token.balanceOf(address(pool)), TOKENS_IN_POOL);
        assertEq(pool.maxFlashLoan(address(token)), TOKENS_IN_POOL);
        assertEq(pool.flashFee(address(token), 0), 0);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function check_selfie() public checkSolvedByPlayer {
        SymbolicAttacker attacker = new SymbolicAttacker();
        console.log("GlobalStorage\t", address(glob));
        console.log("token\t\t", address(token));
        console.log("governance\t", address(governance));
        console.log("pool\t\t", address(pool));
        console.log("attacker\t\t", address(attacker));
        attacker.preload(pool, token);
        uint256 warp = svm.createUint256("preattack_warp");
        vm.warp(block.timestamp + warp); // wait for symbolic time between transactions
        attacker.attack();
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        assert (token.balanceOf(address(pool)) >= TOKENS_IN_POOL);

        // Check allowance changes
        address symbolicSpender = svm.createAddress("symbolicSpender");
        assert (token.allowance(address(pool), symbolicSpender) == 0);
        assert (token.allowance(address(governance), symbolicSpender) == 0);

        // Check if governance's _votingToken may be changed
        assert (governance._votingToken() == token);

        // Check number of registered actions
        //assert (governance._actionCounter() == 1);
    }
}
