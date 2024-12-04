// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "./POCTarget.sol";

contract POCEchidna {
    POCTarget target;

    constructor() public payable {
        target = new POCTarget();
    }

    function echidna_isWorking() public returns (bool) {
        return target.a() != 1;
    }
}
