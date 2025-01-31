// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {NaiveReceiverPool, Multicall, WETH} from "../../src/naive-receiver/NaiveReceiverPool.sol";
import {FlashLoanReceiver} from "../../src/naive-receiver/FlashLoanReceiver.sol";
import {BasicForwarder} from "../../src/naive-receiver/BasicForwarder.sol";
import "lib/GlobalStorage.sol";
import "./SymbolicAttacker.sol";

contract NaiveReceiverChallenge is Test {
    address deployer = address(0xcafe0000);
    address recovery = address(0xcafe0002);
    address player;
    uint256 playerPk;

    uint256 constant WETH_IN_POOL = 1000e18;
    uint256 constant WETH_IN_RECEIVER = 10e18;

    GlobalStorage glob;
    NaiveReceiverPool pool;
    WETH weth;
    FlashLoanReceiver receiver;
    BasicForwarder forwarder;

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
        //(player, playerPk) = makeAddrAndKey("player");
        player = address(0xcafe0001);
        startHoax(deployer, 1 << 80);

        glob = new GlobalStorage();

        // Deploy WETH
        weth = new WETH();

        // Deploy forwarder
        forwarder = new BasicForwarder();

        // Deploy pool and fund with ETH
        pool = new NaiveReceiverPool{value: WETH_IN_POOL}(address(forwarder), payable(weth), deployer);

        // Deploy flashloan receiver contract and fund it with some initial WETH
        receiver = new FlashLoanReceiver(address(pool));
        weth.deposit{value: WETH_IN_RECEIVER}();
        weth.transfer(address(receiver), WETH_IN_RECEIVER);

        glob.add_addr_name_pair(address(weth), "WETH");
        glob.add_addr_name_pair(address(forwarder), "BasicForwarder");
        //glob.add_addr_name_pair(address(pool), "NaiveReceiverPool");
        vm.stopPrank();
    }

    function test_assertInitialState() public {
        // Check initial balances
        assertEq(weth.balanceOf(address(pool)), WETH_IN_POOL);
        assertEq(weth.balanceOf(address(receiver)), WETH_IN_RECEIVER);

        // Check pool config
        assertEq(pool.maxFlashLoan(address(weth)), WETH_IN_POOL);
        assertEq(pool.flashFee(address(weth), 0), 1 ether);
        assertEq(pool.feeReceiver(), deployer);

        // Cannot call receiver
        vm.expectRevert(bytes4(0x48f5c3ed));
        receiver.onFlashLoan(
            deployer,
            address(weth), // token
            WETH_IN_RECEIVER, // amount
            1 ether, // fee
            bytes("") // data
        );
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function check_naiveReceiver() public checkSolvedByPlayer {
        SymbolicAttacker attacker = new SymbolicAttacker();
        console.log("GlobalStorage\t", address(glob));
        console.log("WETH\t\t", address(weth));
        console.log("BasicForwarder\t", address(forwarder));
        console.log("NaiveReceiverPool\t", address(pool));
        console.log("FlashLoanReceiver\t", address(receiver));
        console.log("attacker\t\t", address(attacker));
        attacker.attack();
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        assert (weth.balanceOf(address(pool)) >= WETH_IN_POOL || 
                weth.balanceOf(address(receiver)) >= WETH_IN_RECEIVER);
    }
}
