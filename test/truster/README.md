# Halmos vs Truster
## Halmos version
halmos 0.2.1.dev16+g1502e46 was used in this article
## Foreword
It is strongly assumed that the reader is familiar with the previous article on solving "Unstoppable" (ADD LINK), since the main ideas here are largely repeated and we will not dwell on them again. It should also be clearly stated that we have postponed the "Naive-receiver"(ADD LINK) solution for now, because it is in "Truster" that further necessary techniques for the "Naive-receiver" solution are described. In order not to mislead the reader and not to rush ahead, this order of presentation of the material was chosen.
## Idea overview
Based on what we already know, we will again try to make an attacker contract that would symbolically execute some transaction and hope that this will lead to the attack we need. But will it be enough this time?
## Preparation for the attack
### Common prerequisites 
1. Copy Truster.t.sol file to Truster_Halmos.t.sol. All Halmos-related changes should be done here.
2. Rename **"test_truster()"** to **"check_truster()"**, so Halmos will execute this test symbolically.
3. Avoid using **makeAddr()** cheatcode:
    ```solidity
    address deployer = address(0xcafe0000);
    address player = address(0xcafe0001);
    address recovery = address(0xcafe0002);
    ```
4. vm.getNonce() is unsupportable cheat-code. However, we can be sure that the player will perform only one transaction, since all the work will be done under SymbolicAttacker anyway. Let's remove this check.
### Deploying SymbolicAttacker contract
We still have the same attack technique through the SymbolicAttacker contract. However, this time we have nothing to transfer to it - the player has no additional resources, so the deployment will look a little easier. Also, don't forget to print all the addresses of contracts - this is very useful information. 
```solidity
function check_truster() public checkSolvedByPlayer {
    SymbolicAttacker attacker = new SymbolicAttacker();
    attacker.attack();
}
```
### SymbolicAttacker implementation
Let's try to use the same code and perform some symbolic transaction:
```solidity
// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "halmos-cheatcodes/SymTest.sol";
import "forge-std/Test.sol";

contract SymbolicAttacker is Test, SymTest {
	function attack() public {
        address target = svm.createAddress("target");
        vm.assume (target != address(this)); // Avoid recursion
        bytes memory data = svm.createBytes(100, 'data');
        target.call(data);
    }
}
```
### _isSolved() implementation
The original checks look like:
```solidity
function  _isSolved() private {
...
assertEq(token.balanceOf(address(pool)), 0, "Pool still has tokens");
assertEq(token.balanceOf(recovery), TOKENS_IN_POOL, "Not enough tokens in recovery account");
}
```
Then the opposite check will look like this:
```solidity
function  _isSolved() private {
    ...
    assert(token.balanceOf(address(pool)) != 0 || token.balanceOf(recovery) != TOKENS_IN_POOL);
}
```
### Starting Halmos
```javascript
$ halmos --solver-timeout-assertion 0 --function check_truster
...
Running 1 tests for test/truster/Truster_Halmos.t.sol:TrusterChallenge
[console.log] token      0x00000000000000000000000000000000000000000000000000000000aaaa0002
[console.log] pool       0x00000000000000000000000000000000000000000000000000000000aaaa0003
[console.log] attacker   0x00000000000000000000000000000000000000000000000000000000aaaa0004
[PASS] check_truster() (paths: 28, time: 0.74s, bounds: [])
Symbolic test result: 1 passed; 0 failed; time: 0.82s      
```
And... nothing :(. Passing the test means that it didn't find the way to break this invariant. Let's figure out what's wrong.
## Debugging and solutions
Execute this test in verbose mode:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_truster  -vvvvv
...
Path #28:
    - Not(halmos_target_address_eb8bd05_01 == 0xaaaa0004)
    - halmos_target_address_eb8bd05_01 == 0xaaaa0003
    - Extract(0x31f, 0x300, halmos_data_bytes_80d9faf_02) == 0xab19e0c0
...
Trace:
    CALL TrusterChallenge::0xec4154cf()
        CALL hevm::startPrank(0x00000000000000000000000000000000000000000000000000000000cafe000100000000000000000000000000000000000000000000000000000000cafe0001)
        ...
            STATICCALL svm::createBytes(0x0000000000000000000000000000000000000000000000000000000000000064000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000046461746100000000000000000000000000000000000000000000000000000000)
            ↩ Concat(0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000064, halmos_data_bytes_80d9faf_02())
            CALL 0xaaaa0003::Extract(halmos_data_bytes_80d9faf_02())(Extract(halmos_data_bytes_80d9faf_02())) // !!!THIS IS A PROBLEM!!!
            ↩ REVERT 0x (error: Revert())
...
```
Let's analyze this reverted path, since this is an unpredictable revert from non-view function.
In general, we are interested in these lines:
```javascript
- Extract(0x31f, 0x300, halmos_data_bytes_80d9faf_02) == 0xab19e0c0
...
CALL 0xaaaa0003::Extract(halmos_data_bytes_80d9faf_02())(Extract(halmos_data_bytes_80d9faf_02()))
↩ REVERT 0x (error: Revert())
```
**0xaaaa0003** is the pool address. **0xab19e0c0** is the **flashLoan** function selector:
```javascript
$ cast 4b 0xab19e0c0
flashLoan(uint256,address,address,bytes)
```
In this case, Halmos tries to resolve the parameters of some external function, but this leads to an immediate revert. Often, this means that we simply do not have enough length for our symbolic calldata. So, do we just need to create a larger calldata?
```solidity
contract SymbolicAttacker is Test, SymTest {
	function attack() public {
	...
	    bytes memory data = svm.createBytes(10000, 'data'); // 100 -> 10000
	...
	}
```
And execute:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_truster
...
[ERROR] check_truster() (paths: 38, time: 3.80s, bounds: [])
WARNING:halmos:Encountered symbolic CALLDATALOAD offset: 4 + Extract(79199, 78944, halmos_data_bytes_8bdc959_02)
Symbolic test result: 0 passed; 1 failed; time: 3.90s
```
Hmm, something new. What this warning actually means is that we're passing some calldata bytes to the function as a parameter, but we're doing it via a symbolic call. In simple words, Halmos does not understand where to put "calldata from parameter" in our symbolic calldata and throws an error. 
Let's not delay, it is obvious that this function is our "flashLoan". Its 4th parameter is **"bytes calldata data"**:
```solidity
contract TrusterLenderPool is ReentrancyGuard {
...
function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
```
Fortunately, Halmos provides a special cheat-code for such cases: svm.createCalldata(). All we need to generate valid calldata is the contract type passed as a parameter to this cheat-code. One of the most obvious ways to use it in our attacker is this piece of code:
```solidity
contract SymbolicAttacker is Test, SymTest {
	function attack() public {
        address target = svm.createAddress("target");
        bytes memory data;
        vm.assume (target != address(this)); // Avoid recursion
        if (target == address(0xaaaa0002)) { // token
            data = svm.createCalldata("DamnValuableToken");
        }
        if (target == address(0xaaaa0003)) { // pool
            data = svm.createCalldata("TrusterLenderPool");
        }
        else {
            revert();
        }
        target.call(data);
    }
}
```
Run:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_truster
...
[ERROR] check_truster() (paths: 193, time: 10.48s, bounds: []) 
WARNING:halmos:Encountered symbolic CALLDATALOAD offset: 4 + Extract(7391, 7136, p_data_bytes_9090625_07)
```
What? Same error again? Actually no. Firstly, the number of paths has increased: 193 against 38, and secondly, this one now appears in another function:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_truster -vvvvv
Path #108:
...
Trace:
            CALL 0xaaaa0003::flashLoan(...)
            ...
                CALL 0xaaaa0003::Extract(p_data_bytes_334a71c_07())(Extract(p_data_bytes_334a71c_07()))
                ↩ CALLDATALOAD 0x (error: NotConcreteError('symbolic CALLDATALOAD offset: 4 + Extract(7391, 7136, p_data_bytes_334a71c_07)'))
...
```
The error is some symbolic call in **TrusterLenderPool::flashLoan()** function:
```solidity
function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
...
{
...
    target.functionCall(data);
}
```
Yes, since the **data** parameter also turned out to be symbolic, we got into the same pattern again and got the same error. However, this time, knowing that we can get to a symbolic call of a symbolic address in any contract, we will use a more universal solution!
## Global storage
Let's create a library global storage contract that can be accessed from anywhere:
```solidity
// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "./halmos-cheatcodes/src/SymTest.sol";
import {Test, console} from "forge-std/Test.sol";

contract GlobalStorage {
    // uint256->address mapping to have an ability to iterate over addresses
    mapping (uint256 => address) addresses;
    mapping (address => string) names_by_addr;

    uint256 addresses_list_size = 0;

    // Addresses and names information is stored using this setter
    function add_addr_name_pair (address addr, string memory name) public {
        addresses[addresses_list_size] = addr;
        addresses_list_size++;
        names_by_addr[addr] = name;
    }

    /*
    ** It is expected to receive a symbolic address as a parameter
    ** This function should return some concrete address and its name.
    ** In the case of symbolic execution, the brute force over addresses
    ** is happening here!
    */
    function get_concrete_from_symbolic (address /*symbolic*/ addr) public view 
                                        returns (address ret, string memory name) 
    {
        for (uint256 i = 0; i < addresses_list_size; i++) {
            if (addresses[i] == addr) {
                return (addresses[i], names_by_addr[addr]);
            }
        }
        revert(); // Ignore cases when addr is not some concrete known address
    }
}
```

We will not dwell on the implementation details of this contract. I will only say that this is a contract in which you can store address->contract name pairs. And also with its help you can conveniently brute force these pairs symbolically. It is easier to show how to use it in practice. First, let's prepare Global Storage in Truster_Halmos.t.sol:
```solidity
...
import "lib/GlobalStorage.sol";
...
contract TrusterChallenge is Test {
...
    GlobalStorage public glob; // Add global storage contract
    DamnValuableToken public token;
...
    function setUp() public {
    ...
        // Deploy global storage. It'll have a "0xaaaa0002" address
        glob = new GlobalStorage();
    ...
        glob.add_addr_name_pair(address(token), "DamnValuableToken");
        glob.add_addr_name_pair(address(pool), "TrusterLenderPool");
        vm.stopPrank();
    }
...
```
We will use it in SymbolicAttacker:
```solidity
// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "halmos-cheatcodes/SymTest.sol";
import "forge-std/Test.sol";
import "lib/GlobalStorage.sol";

contract SymbolicAttacker is Test, SymTest {
    // We can hardcode this address for convenience
    GlobalStorage glob = GlobalStorage(address(0xaaaa0002)); 

	function attack() public {
        address target = svm.createAddress("target");
        string memory name;
        //Get some concrete target-name pair
        (target, name) = glob.get_concrete_from_symbolic(target);
        bytes memory data = svm.createCalldata(name);
        target.call(data);
    }
}
```
And in TrusterLenderPool:
```solidity
...
GlobalStorage glob = GlobalStorage(address(0xaaaa0002)); 
...
// Symbolic flashloan function
function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
    external
    nonReentrant
    returns (bool)
{
    uint256 balanceBefore = token.balanceOf(address(this));

    token.transfer(borrower, amount);

    string memory name;
    (target, name) = glob.get_concrete_from_symbolic(target);
    // Don't use "data". Use "newdata" instead
    bytes memory newdata = svm.createCalldata(name);
    target.functionCall(newdata);

    if (token.balanceOf(address(this)) < balanceBefore) {
        revert RepayFailed();
    }

    return true;
}
```
And run Halmos:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_truster
...
[console.log] glob       0x00000000000000000000000000000000000000000000000000000000aaaa0002
[console.log] token      0x00000000000000000000000000000000000000000000000000000000aaaa0003
[console.log] pool       0x00000000000000000000000000000000000000000000000000000000aaaa0004
[console.log] attacker   0x00000000000000000000000000000000000000000000000000000000aaaa0005
[PASS] check_truster() (paths: 132, time: 8.24s, bounds: [])
```
Halmos still can't find a counterexample. But at least now there are no such errors and all functions are covered. Let's go to the next step!
## Another transaction
Finally, we got to the most interesting part. If the problem is not solved in one transaction, we will add another one:
```solidity
contract SymbolicAttacker is Test, SymTest {
...
    function execute_tx() private {
        address target = svm.createAddress("target");
        string memory name;
        //Get some concrete target-name pair
        (target, name) = glob.get_concrete_from_symbolic(target);
        bytes memory data = svm.createCalldata(name);
        target.call(data);
    }

	function attack() public {
        execute_tx();
        execute_tx();
    }
}
```
Run:
```javascript

```






```javascript























```




