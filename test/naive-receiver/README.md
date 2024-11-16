# Halmos vs Truster
## Halmos version
halmos 0.2.1.dev19+g4e82a90 was used in this article
## Foreword
It is strongly assumed that the reader is familiar with the previous articles on solving "Unstoppable", and "Truster" (ADD LINKS), since the main ideas here are largely repeated and we will not dwell on them again.
## Preparation
### Common prerequisites
1. Copy NaiveReceiver.t.sol file to NaiveReceiver_Halmos.t.sol. We will work in this file.
2. Rename "test_naiveReceiver()" to "check_naiveReceiver()", so Halmos will execute this test symbolically.
3. Avoid using makeAddr() cheatcode:
    ```solidity
        address deployer = address(0xcafe0000);
        address recovery = address(0xcafe0002);
    ```
    In this task, for the first time, we have a player's private key in addition to the player address. However, we will ignore it, since we already know that Halmos is not good at cryptography. But we will behave as if we have this key in all places where it might be needed.
    ```solidity
    function setUp() public {
        //(player, playerPk) = makeAddrAndKey("player");
        player = address(0xcafe0001);
        ...
    ```
4. vm.getNonce() is unsupportable cheat-code. Delete it in _isSolved() function.
5. Create GlobalStorage contract and save all address-name pairs:
    ```solidity
    ...
    import "lib/GlobalStorage.sol";
    ...
    contract NaiveReceiverChallenge is Test {
    ...
        GlobalStorage glob;
        NaiveReceiverPool pool;
    ...
        function setUp() public {
            ...
            glob = new GlobalStorage();
            ...
            glob.add_addr_name_pair(address(weth), "WETH");
            glob.add_addr_name_pair(address(forwarder), "BasicForwarder");
            glob.add_addr_name_pair(address(pool), "NaiveReceiverPool");
            glob.add_addr_name_pair(address(receiver), "FlashLoanReceiver");
            vm.stopPrank();
        }
        ...
    }
    ```
6. Print all contract addresses, including the upcoming SymbolicAttacker:
    ```solidity
    function check_naiveReceiver() public checkSolvedByPlayer {
        ...
        SymbolicAttacker attacker = new SymbolicAttacker();
        console.log("GlobalStorage\t", address(glob));
        console.log("WETH\t\t", address(weth));
        console.log("BasicForwarder\t", address(forwarder));
        console.log("NaiveReceiverPool\t", address(pool));
        console.log("FlashLoanReceiver\t", address(receiver));
        console.log("attacker\t\t", address(attacker));
        ...
    ```
     ```javascript
    $ halmos --solver-timeout-assertion 0 --function check_naiveReceiver
    [console.log] GlobalStorage      0x00000000000000000000000000000000000000000000000000000000aaaa0002
    [console.log] WETH               0x00000000000000000000000000000000000000000000000000000000aaaa0003
    [console.log] BasicForwarder     0x00000000000000000000000000000000000000000000000000000000aaaa0004
    [console.log] NaiveReceiverPool  0x00000000000000000000000000000000000000000000000000000000aaaa0005
    [console.log] FlashLoanReceiver  0x00000000000000000000000000000000000000000000000000000000aaaa0006
    [console.log] attacker           0x00000000000000000000000000000000000000000000000000000000aaaa0007
    ```
### _isSolved() implementation
The original checks look like:
```solidity
// The flashloan receiver contract has been emptied
assertEq(weth.balanceOf(address(receiver)), 0, "Unexpected balance in receiver contract");
// Pool is empty too
assertEq(weth.balanceOf(address(pool)), 0, "Unexpected balance in pool");
// All funds sent to recovery account
assertEq(weth.balanceOf(recovery), WETH_IN_POOL + WETH_IN_RECEIVER, "Not enough WETH in recovery account");
```
Then opposite assert is:
```solidity
assert( weth.balanceOf(address(receiver)) != 0 || 
        weth.balanceOf(address(pool)) != 0 || 
        weth.balanceOf(recovery) != WETH_IN_POOL + WETH_IN_RECEIVER);
```
## Improvement of coverage
Let's start with a single-transaction SymbolicAttacker to make sure all paths in target contracts are covered:
```solidity
function check_naiveReceiver() public checkSolvedByPlayer {
    ...
    attacker.attack();
}
```
```solidity
// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "halmos-cheatcodes/SymTest.sol";
import "forge-std/Test.sol";
import "lib/GlobalStorage.sol";

contract SymbolicAttacker is Test, SymTest {
    // We can hardcode this address for convenience
    GlobalStorage glob = GlobalStorage(address(0xaaaa0002)); 

    function execute_tx() private {
        address target = svm.createAddress("target");
        bytes memory data;
        //Get some concrete target-name pair
        (target, data) = glob.get_concrete_from_symbolic(target);
        target.call(data);
    }

	function attack() public {
        execute_tx();
    }
}
```
### Issue #338
If we are trying to run Halmos in the current contracts state, it will fail:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_naiveReceiver
...
WARNING:halmos:path.append(false)
(see https://github.com/a16z/halmos/wiki/warnings#internal-error)
...
WARNING:halmos:check_naiveReceiver(): all paths have been reverted; the setup state or inputs may have been too restrictive.
(see https://github.com/a16z/halmos/wiki/warnings#revert-all)
[ERROR] check_naiveReceiver() (paths: 0, time: 0.07s, bounds: [])
```
This is a known Halmos issue https://github.com/a16z/halmos/issues/338 which has not yet been fixed at the time of writing. We will not delve into the very cause of this problem. I will say only that there is an easy bypass for it. Just change
```solidity
startHoax(deployer);
```
to
```solidity
startHoax(deployer, 1 << 80);
```
### Symbolic calldata refactoring
Let's practice using GlobalStorage again to replace the symbolic calldata call. 









```javascript
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
```