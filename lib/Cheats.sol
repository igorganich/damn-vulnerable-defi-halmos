import "forge-std/Test.sol";
import "./halmos-cheatcodes/src/SymTest.sol";

abstract contract Cheats {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    SVM internal constant svm = SVM(address(uint160(uint256(keccak256("svm cheat code")))));
}
