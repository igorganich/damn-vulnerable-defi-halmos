// SPDX-License-Identifier: MIT

pragma solidity =0.8.25;

import "./Cheats.sol";

contract GlobalStorage is FoundryCheats, HalmosCheats {
    constructor() {
        add_banned_function_selector(bytes4(keccak256("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)")));
        add_banned_function_selector(bytes4(keccak256("delegateBySig(address,uint256,uint256,uint8,bytes32,bytes32)")));
    }

    //SymbolicAttacker address
    address attacker;

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

    function set_attacker_addr(address addr) public {
        _vm.assume(attacker == address(0x0));
        attacker = addr;
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
    function get_addr_data_selector(address /*symbolic*/ addr) private view
                                    returns (address ret, bytes memory data, bytes4 selector)
    {
        selector = _svm.createBytes4("selector");
        for (uint256 i = 0; i < addresses_list_size; i++) {
            if (addresses[i] == addr) {
                string memory name = names_by_addr[addresses[i]];
                ret = addresses[i];
                /*
                * Using the symbolic boolean variable "is_implementation" forces Halmos to separately consider
                * 2 cases: where the interface of the proxy itself or its implementation is used.
                */
                if (keccak256(bytes(name)) == keccak256("ERC1967Proxy")) {
                    bool is_implementation = _svm.createBool("is_implementation");
                    if (is_implementation) {
                        address imp = get_ERC1967Proxy_implementation(addresses[i]);
                        name = names_by_addr[imp];
                    }
                } 
                data = _svm.createCalldata(name);
                _vm.assume(selector == bytes4(data));
                return (ret, data, selector);
            }
        }
        _vm.assume(attacker != address(0x0));
        if (addr == attacker)
        {
            data = _svm.createBytes(1000, "attacker_fallback_bytes");
            _vm.assume(bytes4(data) == bytes4(keccak256("attacker_fallback_selector()")));
            return (attacker, data, selector);
        }
        _vm.assume(false); // Ignore cases when addr is not some concrete known address
    }

    function get_concrete_from_symbolic (address /*symbolic*/ addr) public view 
                                        returns (address ret, bytes memory data) 
    {
        bytes4 selector;
        (ret, data, selector) = get_addr_data_selector(addr);
    }

    /*
    ** This function has the same purpose as get_concrete_from_symbolic,
    ** but applies optimizations and heuristics.
    */
    function get_concrete_from_symbolic_optimized (address /*symbolic*/ addr) public
                                        returns (address ret, bytes memory data) 
    {
        bytes4 selector;
        (ret, data, selector) = get_addr_data_selector(addr);

        for (uint256 s = 0; s < banned_selectors_size; s++) {
            _vm.assume(selector != banned_selectors[s]);
        }
        for (uint256 s = 0; s < used_selectors_size; s++) {
            _vm.assume(selector != used_selectors[s]);
        }
        used_selectors[used_selectors_size] = selector;
        used_selectors_size++;
    }

    /*
    ** The logic of this function is similar to the logic of get_concrete_from_symbolic, 
    ** with the difference that this time the name of the contract is returned 
    ** instead of the ready calldata
    */
    function get_contract_name_by_address (address /*symbolic*/ addr ) public view
                                        returns (string memory name)
    {
        for (uint256 i = 0; i < addresses_list_size; i++) {
            if (addresses[i] == addr) {
                name = names_by_addr[addresses[i]];
                return name;
            }
        }
        _vm.assume(false);// Ignore cases when addr is not some concrete known address
    }

    function get_ERC1967Proxy_implementation(address proxy) public view 
                                            returns (address impl){
        // Check vault implementation immutability
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        bytes32 result = _vm.load(address(proxy), slot);
        impl = address(uint160(uint256(result)));
        return impl;
    }
}
