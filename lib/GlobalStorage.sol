// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "./halmos-cheatcodes/src/SymTest.sol";
import {Test, console} from "forge-std/Test.sol";

contract GlobalStorage is Test, SymTest {
    // uint256->address mapping to have an ability to iterate over addresses
    mapping (uint256 => address) addresses;
    mapping (address => string) names_by_addr;
    uint256 addresses_list_size = 0;

    mapping (uint256 => bytes4) used_selectors;
    uint256 used_selectors_size = 0;

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

    /*
    ** This function has the same purpose as get_concrete_from_symbolic, 
    ** but applies optimizations and heuristics.
    */
    function get_concrete_from_symbolic_optimized (address /*symbolic*/ addr) public 
                                        returns (address ret, bytes memory data) 
    {
        for (uint256 i = 0; i < addresses_list_size; i++) {
            if (addresses[i] == addr) {
                string memory name = names_by_addr[addresses[i]];
                ret = addresses[i];
                data = svm.createCalldata(name);
                bytes4 selector = svm.createBytes4("selector");
                vm.assume(selector == bytes4(data));
                // Not DamnValuableVotes::permit
                vm.assume(selector != bytes4(keccak256("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)")));
                // Not DamnValuableVotes::delegateBySig
                vm.assume(selector != bytes4(keccak256("delegateBySig(address,uint256,uint256,uint8,bytes32,bytes32)")));
                for (uint256 s = 0; s < used_selectors_size; s++) {
                    vm.assume(selector != used_selectors[i]);
                }
                used_selectors[used_selectors_size] = selector;
                used_selectors_size++;
                return (ret, data);
            }
        }
        revert(); // Ignore cases when addr is not some concrete known address
    }
}