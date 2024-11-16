// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "./halmos-cheatcodes/src/SymTest.sol";
import {Test, console} from "forge-std/Test.sol";

contract GlobalStorage is Test, SymTest {
    // uint256->address mapping to have an ability to iterate over addresses
    mapping (uint256 => address) addresses;
    mapping (address => string) names_by_addr;

    uint256 addresses_list_size = 0;

    // Addresses and names information is stored using this setter
    function add_addr_name_pair (address addr, string memory name) public {
        addresses[addresses_list_size] = addr;
        addresses_list_size++;
        names_by_addr[addr] = name;
    }

    /*
    ** if addr is a concrete value, this returns (addr, symbolic calldata for addr)
    ** if addr is symbolic, execution will split for each feasible case and it will return 
    **      (addr0, symbolic calldata for addr0), (addr1, symbolic calldata for addr1), 
            ..., and so on (one pair per path)
    ** if addr is symbolic but has only 1 feasible value (e.g. with vm.assume(addr == ...)), 
            then it should behave like the concrete case
    */
    function get_concrete_from_symbolic (address /*symbolic*/ addr) public view 
                                        returns (address ret, bytes memory data) 
    {
        for (uint256 i = 0; i < addresses_list_size; i++) {
            if (addresses[i] == addr) {
                string memory name = names_by_addr[addresses[i]];
                ret = addresses[i];
                data = svm.createCalldata(name);
                bytes4 selector = svm.createBytes4("selector");
                vm.assume(selector == bytes4(data));
                return (ret, data);
            }
        }
        revert(); // Ignore cases when addr is not some concrete known address
    }
}