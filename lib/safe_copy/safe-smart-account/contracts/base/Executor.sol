// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;
import "../common/Enum.sol";
import {Test, console} from "forge-std/Test.sol";
import "lib/GlobalStorage.sol";

/**
 * @title Executor - A contract that can execute transactions
 * @author Richard Meissner - @rmeissner
 */
abstract contract Executor is FoundryCheats, HalmosCheats {
    GlobalStorage glob = GlobalStorage(address(0xaaaa0002));
    /**
     * @notice Executes either a delegatecall or a call with provided parameters.
     * @dev This method doesn't perform any sanity check of the transaction, such as:
     *      - if the contract at `to` address has code or not
     *      It is the responsibility of the caller to perform such checks.
     * @param to Destination address.
     * @param value Ether value.
     * @param data Data payload.
     * @param operation Operation type.
     * @return success boolean flag indicating if the call succeeded.
     */
    function execute(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 txGas
    ) internal returns (bool success) {
        uint snap0 = _vm.snapshotState();
        if (operation == Enum.Operation.DelegateCall) {
            // solhint-disable-next-line no-inline-assembly
            _vm.assume(to == address(0xaaaa0007));
            bytes memory mydata = abi.encodeWithSignature("handle_delegatecall()");
            assembly {
                success := delegatecall(txGas, to, add(mydata, 0x20), mload(mydata), 0, 0)
            }
        } else {
            address target = _svm.createAddress("execute_target");
            bytes memory mydata;
            //Get some concrete target-name pair
            (target, mydata) = glob.get_concrete_from_symbolic_optimized(target);
            target.call(mydata);
        }
        uint snap1 = _vm.snapshotState();
        _vm.assume(snap0 != snap1);
    }
}
