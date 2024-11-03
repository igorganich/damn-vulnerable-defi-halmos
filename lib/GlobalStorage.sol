// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "./halmos-cheatcodes/src/SymTest.sol";
import {Test, console} from "forge-std/Test.sol";

contract GlobalStorage {
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
    ** It is expected to receive a symbolic address as a parameter
    ** This function should return some concrete address and its name.
    ** In the case of symbolic execution, the brute force over addresses
    ** is happening here!
    */
    function get_concrete_from_symbolic (address /*symbolic*/ addr) public view 
                                        returns (address ret, string memory name) 
    {
        for (uint256 i = 0; i < addresses_list_size; i++) {
            if (addresses[i] == addr) {
                return (addresses[i], names_by_addr[addr]);
            }
        }
        revert(); // Ignore cases when addr is not some concrete known address
    }
}