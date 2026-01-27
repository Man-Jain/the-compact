// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import {
  SignerVerificationAllocator
} from "../src/examples/allocator/SignerVerificationAllocator.sol";

contract SignerVerificationAllocatorScript is Script {
  function run() public returns (SignerVerificationAllocator allocator) {
    address signer = vm.envAddress("SIGNER");

    vm.startBroadcast();
    allocator = new SignerVerificationAllocator(signer);
    vm.stopBroadcast();

    console2.log("SignerVerificationAllocator:", address(allocator));
  }
}
