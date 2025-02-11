// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {ClimberVault} from "../../src/climber/ClimberVault.sol";
import {ClimberTimelock, CallerNotTimelock, PROPOSER_ROLE, ADMIN_ROLE} from "../../src/climber/ClimberTimelock.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";

import "lib/GlobalStorage.sol";
import "./SymbolicAttacker.sol";


contract ClimberChallenge is Test, SymTest {
    address deployer = address(0xcafe0000);
    address player = address(0xcafe0001);
    address recovery = address(0xcafe0002);
    address proposer = address(0xcafe0003);
    address sweeper = address(0xcafe0004);

    uint256 constant VAULT_TOKEN_BALANCE = 10_000_000e18;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 0.1 ether;
    uint256 constant TIMELOCK_DELAY = 60 * 60;

    GlobalStorage glob;
    ClimberVault vault;
    ClimberTimelock timelock;
    DamnValuableToken token;

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
        vm.deal(player, PLAYER_INITIAL_ETH_BALANCE);

        // Deploy the vault behind a proxy,
        // passing the necessary addresses for the `ClimberVault::initialize(address,address,address)` function
        vault = ClimberVault(
            address(
                new ERC1967Proxy(
                    address(new ClimberVault()), // implementation
                    abi.encodeCall(ClimberVault.initialize, (deployer, proposer, sweeper)) // initialization data
                )
            )
        );

        // Get a reference to the timelock deployed during creation of the vault
        timelock = ClimberTimelock(payable(vault.owner()));

        // Deploy token and transfer initial token balance to the vault
        token = new DamnValuableToken();
        token.transfer(address(vault), VAULT_TOKEN_BALANCE);

        glob.add_addr_name_pair(address(vault), "ERC1967Proxy");
        glob.add_addr_name_pair(address(timelock), "ClimberTimelock");
        glob.add_addr_name_pair(address(token), "DamnValuableToken");

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public {
        assertEq(player.balance, PLAYER_INITIAL_ETH_BALANCE);
        assertEq(vault.getSweeper(), sweeper);
        assertGt(vault.getLastWithdrawalTimestamp(), 0);
        assertNotEq(vault.owner(), address(0));
        assertNotEq(vault.owner(), deployer);

        // Ensure timelock delay is correct and cannot be changed
        assertEq(timelock.delay(), TIMELOCK_DELAY);
        vm.expectRevert(CallerNotTimelock.selector);
        timelock.updateDelay(uint64(TIMELOCK_DELAY + 1));

        // Ensure timelock roles are correctly initialized
        assertTrue(timelock.hasRole(PROPOSER_ROLE, proposer));
        assertTrue(timelock.hasRole(ADMIN_ROLE, deployer));
        assertTrue(timelock.hasRole(ADMIN_ROLE, address(timelock)));

        assertEq(token.balanceOf(address(vault)), VAULT_TOKEN_BALANCE);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function check_climber() public checkSolvedByPlayer {
        SymbolicAttacker attacker = new SymbolicAttacker();
        glob.set_attacker_addr(address(attacker));
        console.log("GlobalStorage\t", address(glob));
        console.log("ClimberVault\t", address(vault));
        console.log("ClimberTimelock\t", address(timelock));
        console.log("token\t\t", address(token));
        console.log("GlobalStorage\t", address(attacker));
        attacker.attack();
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        assert(token.balanceOf(address(vault)) >= VAULT_TOKEN_BALANCE);
        
        // Check allowance changes
        address symbolicSpender = svm.createAddress("symbolicSpender");
        assert(token.allowance(address(vault), symbolicSpender) == 0);
        
        // Check vault roles immutability:
        assert(vault.getSweeper() == sweeper);
        assert(vault.owner() == address(timelock));
        
        // Check vault implementation immutability
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        bytes32 result = vm.load(address(vault), slot);
        address currentImpl = address(uint160(uint256(result)));
        assert(currentImpl == address(0xaaaa0003));
        
        // Check timelock roles immutability
        address symbolicProposer = svm.createAddress("symbolicProposer");
        vm.assume(symbolicProposer != proposer);
        assert(!timelock.hasRole(PROPOSER_ROLE, symbolicProposer));

        address symbolicAdmin = svm.createAddress("symbolicAdmin");
        vm.assume(symbolicAdmin != deployer);
        vm.assume(symbolicAdmin != address(timelock));
        assert(!timelock.hasRole(ADMIN_ROLE, symbolicAdmin));
    }
}
