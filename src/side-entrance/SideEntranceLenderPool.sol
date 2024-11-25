// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

interface IFlashLoanEtherReceiver {
    function execute() external payable;
}

interface IFlashLoanEtherReceiverEchidna {
    function execute(bool is_flashLoan, bool is_withdraw,
                        uint256 uint256_param1) external payable;
}

contract SideEntranceLenderPool {
    mapping(address => uint256) public balances;

    error RepayFailed();

    event Deposit(address indexed who, uint256 amount);
    event Withdraw(address indexed who, uint256 amount);

    function deposit() external payable {
        unchecked {
            balances[msg.sender] += msg.value;
        }
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];

        delete balances[msg.sender];
        emit Withdraw(msg.sender, amount);

        SafeTransferLib.safeTransferETH(msg.sender, amount);
    }

    function flashLoan(uint256 amount) external {
        uint256 balanceBefore = address(this).balance;

        IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();

        if (address(this).balance < balanceBefore) {
            revert RepayFailed();
        }
    }

    // flashLoan for fuzzing
    function _flashLoan(uint256 amount, uint256 uint256_param1,
                        bool bool_param1, bool bool_param2) external {
        uint256 balanceBefore = address(this).balance;

        IFlashLoanEtherReceiverEchidna(msg.sender).execute{value: amount}(bool_param1, bool_param2, uint256_param1);

        if (address(this).balance < balanceBefore) {
            revert RepayFailed();
        }
    }
}