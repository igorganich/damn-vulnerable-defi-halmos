// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {FixedPointMathLib} from "solady/utils/FixedPointMathLib.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {BitMaps} from "@openzeppelin/contracts/utils/structs/BitMaps.sol";
import "forge-std/Test.sol";
import "halmos-cheatcodes/SymTest.sol";

struct Distribution {
    uint256 remaining;
    uint256 nextBatchNumber;
    mapping(uint256 batchNumber => bytes32 root) roots;
    mapping(address claimer => mapping(uint256 word => uint256 bits)) claims;
}

struct Claim {
    uint256 batchNumber;
    uint256 amount;
    uint256 tokenIndex;
    bytes32[] proof;
}

/**
 * An efficient token distributor contract based on Merkle proofs and bitmaps
 */
contract TheRewarderDistributor is Test, SymTest {

    Claim[] public storageInputClaims;
    IERC20[] public storageInputTokens;
    

    using BitMaps for BitMaps.BitMap;

    address public immutable owner = msg.sender;

    mapping(IERC20 token => Distribution) public distributions;

    error StillDistributing();
    error InvalidRoot();
    error AlreadyClaimed();
    error InvalidProof();
    error NotEnoughTokensToDistribute();

    event NewDistribution(IERC20 token, uint256 batchNumber, bytes32 newMerkleRoot, uint256 totalAmount);

    function pushClaim(Claim memory claim) public {
        storageInputClaims.push(claim);
    }

    function pushToken(IERC20 token) public {
        storageInputTokens.push(token);
    }

    function getRemaining(address token) external view returns (uint256) {
        return distributions[IERC20(token)].remaining;
    }

    function getNextBatchNumber(address token) external view returns (uint256) {
        return distributions[IERC20(token)].nextBatchNumber;
    }

    function getRoot(address token, uint256 batchNumber) external view returns (bytes32) {
        return distributions[IERC20(token)].roots[batchNumber];
    }

    function createDistribution(IERC20 token, bytes32 newRoot, uint256 amount) external {
        if (amount == 0) revert NotEnoughTokensToDistribute();
        if (newRoot == bytes32(0)) revert InvalidRoot();
        if (distributions[token].remaining != 0) revert StillDistributing();

        distributions[token].remaining = amount;

        uint256 batchNumber = distributions[token].nextBatchNumber;
        distributions[token].roots[batchNumber] = newRoot;
        distributions[token].nextBatchNumber++;

        SafeTransferLib.safeTransferFrom(address(token), msg.sender, address(this), amount);

        emit NewDistribution(token, batchNumber, newRoot, amount);
    }

    function clean(IERC20[] calldata tokens) external {
        for (uint256 i = 0; i < tokens.length; i++) {
            IERC20 token = tokens[i];
            if (distributions[token].remaining == 0) {
                token.transfer(owner, token.balanceOf(address(this)));
            }
        }
    }

    // Allow claiming rewards of multiple tokens in a single transaction
    // Save original function
    /*
    function claimRewards(Claim[] memory inputClaims, IERC20[] memory inputTokens) external {
        Claim memory inputClaim;
        IERC20 token;
        uint256 bitsSet; // accumulator
        uint256 amount;

        for (uint256 i = 0; i < inputClaims.length; i++) {
            inputClaim = inputClaims[i];

            uint256 wordPosition = inputClaim.batchNumber / 256;
            uint256 bitPosition = inputClaim.batchNumber % 256;

            if (token != inputTokens[inputClaim.tokenIndex]) {
                if (address(token) != address(0)) {
                    if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
                }

                token = inputTokens[inputClaim.tokenIndex];
                bitsSet = 1 << bitPosition; // set bit at given position
                amount = inputClaim.amount;
            } else {
                bitsSet = bitsSet | 1 << bitPosition;
                amount += inputClaim.amount;
            }

            // for the last claim
            if (i == inputClaims.length - 1) {
                if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
            }

            bytes32 leaf = keccak256(abi.encodePacked(msg.sender, inputClaim.amount));
            bytes32 root = distributions[token].roots[inputClaim.batchNumber];

            if (!MerkleProof.verify(inputClaim.proof, root, leaf)) revert InvalidProof();

            inputTokens[inputClaim.tokenIndex].transfer(msg.sender, inputClaim.amount);
        }
    }*/

    /* Fuzzing version
    function claimRewards() external {
        Claim memory inputClaim;
        IERC20 token;
        uint256 bitsSet; // accumulator
        uint256 amount;

        for (uint256 i = 0; i < storageInputClaims.length; i++) {
            inputClaim = storageInputClaims[i];
            if (storageInputTokens[inputClaim.tokenIndex] == 
                IERC20(address(0x62d69f6867A0A084C6d313943dC22023Bc263691))) // weth
            {
                inputClaim.amount = 1171088749244340;
            }
            else if (storageInputTokens[inputClaim.tokenIndex] == 
                IERC20(address(0xb4c79daB8f259C7Aee6E5b2Aa729821864227e84))) // dvt
            {
                inputClaim.amount = 11524763827831882;
            }

            uint256 wordPosition = inputClaim.batchNumber / 256;
            uint256 bitPosition = inputClaim.batchNumber % 256;

            if (token != storageInputTokens[inputClaim.tokenIndex]) {
                if (address(token) != address(0)) {
                    if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
                }

                token = storageInputTokens[inputClaim.tokenIndex];
                bitsSet = 1 << bitPosition; // set bit at given position
                amount = inputClaim.amount;
            } else {
                bitsSet = bitsSet | 1 << bitPosition;
                amount += inputClaim.amount;
            }

            // for the last claim
            if (i == storageInputClaims.length - 1) {
                if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
            }

            //bytes32 leaf = keccak256(abi.encodePacked(msg.sender, inputClaim.amount));
            //bytes32 root = distributions[token].roots[inputClaim.batchNumber];

            //if (!MerkleProof.verify(inputClaim.proof, root, leaf)) revert InvalidProof();

            storageInputTokens[inputClaim.tokenIndex].transfer(msg.sender, inputClaim.amount);
        }
    }*/

    
    // Symbolic version
    function claimRewards(Claim[] memory inputClaims, IERC20[] memory inputTokens) external {
        Claim memory inputClaim;
        IERC20 token;
        uint256 bitsSet; // accumulator
        uint256 amount;
        for (uint256 i = 0; i < inputClaims.length; i++) {
            inputClaim = inputClaims[i];
            uint256 wordPosition = inputClaim.batchNumber / 256;
            uint256 bitPosition = inputClaim.batchNumber % 256;

            address symbolicInputToken = svm.createAddress("SymbolicInputToken");
            if (msg.sender != address(0x44E97aF4418b7a17AABD8090bEA0A471a366305C))
            {
                symbolicInputToken = address(inputTokens[inputClaim.tokenIndex]);
            }
            //if (token != inputTokens[inputClaim]) {
            if (token != IERC20(symbolicInputToken)) {
                if (address(token) != address(0)) {
                    if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
                }
                //token = inputTokens[inputClaim.tokenIndex];
                token = IERC20(symbolicInputToken);
                bitsSet = 1 << bitPosition; // set bit at given position
                amount = inputClaim.amount;
            } else {
                bitsSet = bitsSet | 1 << bitPosition;
                amount += inputClaim.amount;
            }

            // for the last claim
            if (i == inputClaims.length - 1) {
                if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
            }
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
            //inputTokens[inputClaim.tokenIndex].transfer(msg.sender, inputClaim.amount);
            IERC20(token).transfer(msg.sender, inputClaim.amount);
        }
    }
    

    function _setClaimed(IERC20 token, uint256 amount, uint256 wordPosition, uint256 newBits) private returns (bool) {
        uint256 currentWord = distributions[token].claims[msg.sender][wordPosition];
        if ((currentWord & newBits) != 0) return false;

        // update state
        distributions[token].claims[msg.sender][wordPosition] = currentWord | newBits;
        distributions[token].remaining -= amount;

        return true;
    }
}