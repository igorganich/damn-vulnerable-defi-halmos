// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {Safe} from "@safe-global/safe-smart-account/contracts/Safe.sol";
import {SafeProxyFactory} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {WalletRegistry} from "../../src/backdoor/WalletRegistry.sol";
import "lib/GlobalStorage.sol";
import "./SymbolicAttacker.sol";

contract BackdoorChallenge is Test, SymTest {
    address deployer = address(0xcafe0000);
    address player = address(0xcafe0001);
    address recovery = address(0xcafe0002);
    address[] users = [address(0xcafe0003), address(0xcafe0004), address(0xcafe0005), address(0xcafe0006)];

    uint256 constant AMOUNT_TOKENS_DISTRIBUTED = 40e18;

    GlobalStorage glob;
    DamnValuableToken token;
    Safe singletonCopy;
    SafeProxyFactory walletFactory;
    WalletRegistry walletRegistry;

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
        // Deploy Safe copy and factory
        glob = new GlobalStorage();
        singletonCopy = new Safe();
        walletFactory = new SafeProxyFactory();

        // Deploy reward token
        token = new DamnValuableToken();

        // Deploy the registry
        walletRegistry = new WalletRegistry(address(singletonCopy), address(walletFactory), address(token), users);

        // Transfer tokens to be distributed to the registry
        token.transfer(address(walletRegistry), AMOUNT_TOKENS_DISTRIBUTED);

        glob.add_addr_name_pair(address(singletonCopy), "Safe");
        glob.add_addr_name_pair(address(walletFactory), "SafeProxyFactory");
        glob.add_addr_name_pair(address(token), "DamnValuableToken");
        glob.add_addr_name_pair(address(walletRegistry), "WalletRegistry");

        glob.add_banned_function_selector(bytes4(keccak256("createProxyWithNonce(address,bytes,uint256)")));
        glob.add_banned_function_selector(bytes4(keccak256("createChainSpecificProxyWithNonce(address,bytes,uint256)")));
        glob.add_banned_function_selector(bytes4(keccak256("simulateAndRevert(address,bytes)")));

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public {
        assertEq(walletRegistry.owner(), deployer);
        assertEq(token.balanceOf(address(walletRegistry)), AMOUNT_TOKENS_DISTRIBUTED);
        for (uint256 i = 0; i < users.length; i++) {
            // Users are registered as beneficiaries
            assertTrue(walletRegistry.beneficiaries(users[i]));

            // User cannot add beneficiaries
            //vm.expectRevert(0x82b42900); // `Unauthorized()`
            vm.prank(users[i]);
            walletRegistry.addBeneficiary(users[i]);
        }
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function check_backdoor() public checkSolvedByPlayer {
        SymbolicAttacker attacker = new SymbolicAttacker();
        console.log("GlobalStorage\t", address(glob));
        console.log("singletonCopy\t", address(singletonCopy));
        console.log("walletFactory\t", address(walletFactory));
        console.log("token\t\t", address(token));
        console.log("walletRegistry\t", address(walletRegistry));
        console.log("attacker\t\t", address(attacker));
        attacker.attack();
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        for (uint256 i = 0; i < users.length; i++) {
            address wallet = walletRegistry.wallets(users[i]);

            if (wallet != address(0)) {
                assert(token.balanceOf(wallet) >= 10e18);
                address symbolic_spender = svm.createAddress("symbolic_spender");
                assert(token.allowance(wallet, symbolic_spender) == 0);
            }
        }
    }
}
