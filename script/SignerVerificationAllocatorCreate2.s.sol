// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import {
  SignerVerificationAllocator
} from "../src/examples/allocator/SignerVerificationAllocator.sol";

/// @notice Deploys SignerVerificationAllocator with CREATE2 so the same address
///         is used across all networks (same deployer + salt + bytecode + constructor args).
/// @dev Configure [rpc_endpoints] in foundry.toml for each network. Run with --broadcast.
contract SignerVerificationAllocatorCreate2Script is Script {
  bytes32 public constant SIGNER_VERIFICATION_ALLOCATOR_SALT =
    bytes32(uint256(0x53)); // "S" for SignerVerification

  string[4] internal networks = ["optimism", "base", "polygon", "arbitrum"];

  function run() public {
    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
    address signer = vm.envAddress("SIGNER");

    for (uint256 i = 0; i < networks.length; i++) {
      vm.createSelectFork(networks[i]);
      vm.startBroadcast(deployerPrivateKey);

      SignerVerificationAllocator allocator = new SignerVerificationAllocator{
        salt: SIGNER_VERIFICATION_ALLOCATOR_SALT
      }(signer);

      vm.stopBroadcast();

      console2.log(networks[i], "SignerVerificationAllocator:", address(allocator));
    }

    // Expected CREATE2 address (same on all chains)
    address deployer = vm.addr(deployerPrivateKey);
    bytes memory initCode = abi.encodePacked(
      type(SignerVerificationAllocator).creationCode,
      abi.encode(signer)
    );
    bytes32 initCodeHash = keccak256(initCode);
    address predicted = address(
      uint160(
        uint256(
          keccak256(
            abi.encodePacked(
              bytes1(0xff),
              deployer,
              SIGNER_VERIFICATION_ALLOCATOR_SALT,
              initCodeHash
            )
          )
        )
      )
    );
    console2.log("Expected CREATE2 address (all networks):", predicted);
  }
}
