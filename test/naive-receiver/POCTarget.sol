// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

contract POCTarget {
    uint256 public a;
    
    constructor() {
        a = 0;
    }

    function proxycall (bytes calldata data) public {
        address(this).call(data);
    }

    function changea () public {
        if (msg.sender != address(this)) {
            revert();
        }
        if (address(bytes20(msg.data[msg.data.length - 20:])) == address(this)) {
            a = 1;
        }
    }
}