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

    // save original function

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


    // Fuzz flashloan function
    function _flashLoan(uint256 amount, address borrower/*, address target, bytes calldata data*/)
        external
        nonReentrant
        returns (bool)
    {
        uint256 balanceBefore = token.balanceOf(address(this));
        bytes memory data = abi.encodeWithSignature("approve(address,uint256)", 
                            address(0x44E97aF4418b7a17AABD8090bEA0A471a366305C ), 
                            0x0020000000000000000000000000000000000000000000000000000000000000);

        token.transfer(borrower, amount);
        address(0x8Ad159a275AEE56fb2334DBb69036E9c7baCEe9b).functionCall(data);


        if (token.balanceOf(address(this)) < balanceBefore) {
            revert RepayFailed();
        }

        return true;
    }

    // Symbolic flashloan function
    /*function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
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
    }*/
}