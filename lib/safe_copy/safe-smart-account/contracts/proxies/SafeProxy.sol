// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import {Test, console} from "forge-std/Test.sol";
import "lib/GlobalStorage.sol";

/**
 * @title IProxy - Helper interface to access the singleton address of the Proxy on-chain.
 * @author Richard Meissner - @rmeissner
 */
interface IProxy {
    function masterCopy() external view returns (address);
}

/**
 * @title SafeProxy - Generic proxy contract allows to execute all transactions applying the code of a master contract.
 * @author Stefan George - <stefan@gnosis.io>
 * @author Richard Meissner - <richard@gnosis.io>
 */
contract SafeProxy is Test, SymTest{
    address internal singleton;

    bool reent_guard = false;
    GlobalStorage glob = GlobalStorage(address(0xaaaa0002));

    /**
     * @notice Constructor function sets address of singleton contract.
     * @param _singleton Singleton address.
     */
    constructor(address _singleton) {
        require(_singleton != address(0), "Invalid singleton address provided");
        singleton = _singleton;
    }

    function symbolic_fallback() external payable {
        if (reent_guard) {
            revert();
        }
        reent_guard = true;
        //bytes memory initializer_data = svm.createCalldata("Safe");
        address singleton_address;
        bytes memory initializer_data;
        (singleton_address, initializer_data) = glob.get_concrete_from_symbolic_optimized(singleton);
        uint snap0 = vm.snapshotState();
        (bool success,bytes memory returndata) = singleton.delegatecall(initializer_data);
        uint snap1 = vm.snapshotState();
        vm.assume(snap0 != snap1);
        reent_guard = false;
        if (!success) {
            // Revert with the returned data
            assembly {
                revert(add(returndata, 0x20), mload(returndata))
            }
        }

        // Return with the returned data
        assembly {
            return(add(returndata, 0x20), mload(returndata))
        }
    }

   fallback() external payable {
        // Check for mastercopy() call
        if (msg.sig == bytes4(keccak256("mastercopy()"))) {
            assembly {
                mstore(0x00, sload(singleton.slot))
                return(0x00, 32)
            }
        } else {
            _delegateCall();
        }
    }

    function _delegateCall() internal {
        (bool success, bytes memory returndata) = singleton.delegatecall(msg.data);
        if (!success) {
            // Revert with the returned data
            assembly {
                revert(add(returndata, 0x20), mload(returndata))
            }
        }

        // Return with the returned data
        assembly {
            return(add(returndata, 0x20), mload(returndata))
        }
    }
}
