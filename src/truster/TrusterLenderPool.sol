// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {DamnValuableToken} from "../DamnValuableToken.sol";
import "halmos-cheatcodes/SymTest.sol";
import "forge-std/Test.sol";

import "lib/GlobalStorage.sol";

contract TrusterLenderPool is ReentrancyGuard {
    using Address for address;
    // We can hardcode this address for convenience
    GlobalStorage glob = GlobalStorage(address(0xaaaa0002)); 

    DamnValuableToken public immutable token;

    error RepayFailed();

    constructor(DamnValuableToken _token) {
        token = _token;
    }

    // Original function
/*
    function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
        external
        nonReentrant
        returns (bool)
    {
        uint256 balanceBefore = token.balanceOf(address(this));

        token.transfer(borrower, amount);
        target.functionCall(data);

        if (token.balanceOf(address(this)) < balanceBefore) {
            revert RepayFailed();
        }

        return true;
    }
*/
    // Symbolic flashloan function
    function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
        external
        nonReentrant
        returns (bool)
    {
        uint256 balanceBefore = token.balanceOf(address(this));

        token.transfer(borrower, amount);

        // Work with "newdata" like this is the "data"
        bytes memory newdata;
        (target, newdata) = glob.get_concrete_from_symbolic(target);
        target.functionCall(newdata);

        if (token.balanceOf(address(this)) < balanceBefore) {
            revert RepayFailed();
        }

        return true;
    }

/*  // Fuzz flashloan function (Full hint)
    function _flashLoan(uint256 amount, address borrower)
        external
        nonReentrant
        returns (bool)
    {
        uint256 balanceBefore = token.balanceOf(address(this));
        bytes memory data = abi.encodeWithSignature("approve(address,uint256)", 
                            address(0xcafe0002 ), 
                            0x0020000000000000000000000000000000000000000000000000000000000000);

        token.transfer(borrower, amount);
        address(token).functionCall(data);


        if (token.balanceOf(address(this)) < balanceBefore) {
            revert RepayFailed();
        }

        return true;
    }
*/

/*
    // Fuzz flashloan function (brute force)
    function __flashLoan(uint256 amount, address borrower,
                            bool is_token,
                            bool is_approve, address approve_to, uint256 approve_amount,
                            bool is_permit, address permit_owner, address permit_spender, 
                                uint256 permit_value, uint256 permit_deadline, uint8 permit_v,
                                bytes32 permit_r, bytes32 permit_s,
                            bool is_transfer, address transfer_to, uint256 transfer_amount,
                            bool is_transferFrom, address transferFrom_from, 
                                address transferFrom_to, uint256 transferFrom_amount
                            )
        external
        nonReentrant
        returns (bool)
    {
        uint256 balanceBefore = token.balanceOf(address(this));
        
        token.transfer(borrower, amount);
        //target is token
        if (is_token) {
            if (is_approve) {
                token.approve(approve_to, approve_amount);
            }
            else if (is_permit) {
                token.permit(permit_owner, permit_spender, permit_value, 
                                            permit_deadline, permit_v,
                                            permit_r, permit_s);
            }
            else if (is_transfer) {
                token.transfer(transfer_to, transfer_amount);
            }
            else if (is_transferFrom) {
                token.transferFrom(transferFrom_from, transferFrom_to, transferFrom_amount);
            }
        }
        // target is pool
        else {
            bytes memory data = ""; // The only one function in pool is nonReentrant anyway
            address(this).functionCall(data); // Call flashloan itself
        }
        if (token.balanceOf(address(this)) < balanceBefore) {
            revert RepayFailed();
        }
        return true;
    }
    */
}