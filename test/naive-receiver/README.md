# Halmos vs Truster
## Halmos version
halmos 0.2.1.dev19+g4e82a90 was used in this article
## Foreword
It is strongly assumed that the reader is familiar with the previous articles on solving "Unstoppable", and "Truster" (ADD LINKS), since the main ideas here are largely repeated and we will not dwell on them again.
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
        target.call(newdata);
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
function multicall() external virtual returns (bytes[] memory results) {
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
Catastrophe! An hour later, Halmos simply collapsed due to out-of-memory. This is a known problem of symbolic analysis: Path Explosion (add link). Halmos could not handle the symbolic execution of 2 transactions in a setup with such 4 contracts. Here we have reached the Halmos limit, and it will not be possible to solve this problem so straightforwardly. We will have to introduce some heuristic optimizations.
## Optimizations
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
This function is the only function of this contract. In addition, it will not be executed if **msg.sender** is not **NaiveReceiverPool**. Therefore, we can safely delete FlashLoanReceiver from GlobalStorage. And next to that, we optimize the NaiveReceiverPool logic:
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
    vm.assume(target == address(0xaaaa0005));
    target.call(newdata);
}
```
Next to it, there is a cryptographic check of the signature in **_checkRequest**:
```solidity
function _checkRequest(Request calldata request, bytes calldata signature) private view {
...
    address signer = ECDSA.recover(_hashTypedData(getDataHash(request)), signature);
    if (signer != request.from) revert InvalidSigner();
}
```
We already know that tools like Halmos don't do well with cryptographic checks, so we'll have to think logically here. 
Let's remember that under the condition of the problem, we have the player's private key, which we can use to sign forward transactions here. It turns out that the only transfer.from we can pass is the player's address:
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
No, it's still too hard. Much stronger heuristics are needed.
## Heuristics
We have reached the point where we can no longer operate with only stable improvements and expect Halmos to give us a clear solution to the problem in such a clear form as in past challenges. Will have to try to apply some relief by sacrificing likely scenarios that could be covered symbolically.
### Proxy heuristics
Since **BasicForwarder** is essentially just a proxy contract for **NaiveReceiverPool**, and **multicall** is in turn a proxy function for other pool functions, we can try to sacrifice scenarios where we call functions from NaiveReceiverPool directly. On the other hand, we get the benefit of not having duplicate calls to these functions, while not reducing overall code coverage:
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
    vm.assume(target == address(0xaaaa0005));
    vm.assume(bytes4(newdata) == bytes4(keccak256("multicall()")));
    target.call(newdata);
}
```
```javascript
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
```