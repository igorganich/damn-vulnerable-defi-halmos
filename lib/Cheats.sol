import "forge-std/Test.sol";
import "./halmos-cheatcodes/src/SymTest.sol";

abstract contract FoundryCheats {
    Vm internal constant _vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
}

abstract contract HalmosCheats {
    SVM internal constant _svm = SVM(address(uint160(uint256(keccak256("svm cheat code")))));
}
