// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "./Cheats.sol";

contract GlobalStorage is Cheats {
    constructor() {
        add_banned_function_selector(bytes4(keccak256("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)")));
        add_banned_function_selector(bytes4(keccak256("delegateBySig(address,uint256,uint256,uint8,bytes32,bytes32)")));
    }

    // uint256->address mapping to have an ability to iterate over addresses
    mapping (uint256 => address) addresses;
    mapping (address => string) names_by_addr;
    uint256 addresses_list_size = 0;

    mapping (uint256 => bytes4) used_selectors;
    uint256 used_selectors_size = 0;
    mapping (uint256 => bytes4) banned_selectors;
    uint256 banned_selectors_size = 0;

    function add_banned_function_selector(bytes4 selector) public {
        banned_selectors[banned_selectors_size] = selector;
        banned_selectors_size++;
    }

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
                for (uint256 s = 0; s < banned_selectors_size; s++) {
                    vm.assume(selector != banned_selectors[s]);
                }
                for (uint256 s = 0; s < used_selectors_size; s++) {
                    vm.assume(selector != used_selectors[s]);
                }
                used_selectors[used_selectors_size] = selector;
                used_selectors_size++;
                return (ret, data);
            }
        }
        revert(); // Ignore cases when addr is not some concrete known address
    }

    /*
    ** The logic of this function is similar to the logic of get_concrete_from_symbolic, 
    ** with the difference that this time the name of the contract is returned 
    ** instead of the ready calldata
    */
    function get_contract_name_by_address (address /*symbolic*/ addr ) public
                                        returns (string memory name)
    {
        for (uint256 i = 0; i < addresses_list_size; i++) {
            if (addresses[i] == addr) {
                name = names_by_addr[addresses[i]];
                return name;
            }
        }
        vm.assume(false);// Ignore cases when addr is not some concrete known address
    }
}