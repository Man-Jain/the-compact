// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {
  SignerVerificationAllocator
} from "src/examples/allocator/SignerVerificationAllocator.sol";

contract SignerVerificationAllocatorTest is Test {
  bytes32 internal constant COMPACT_DOMAIN_SEPARATOR =
    0x86e7aad2e0029bde18b0d57fc8f265574d4ff8cc5c8b859ed76df2428b57de53;

  SignerVerificationAllocator allocator;
  address owner;
  address signer;
  uint256 signerPk;
  address other;

  function setUp() public {
    owner = makeAddr("owner");
    (signer, signerPk) = makeAddrAndKey("signer");
    other = makeAddr("other");

    vm.prank(owner);
    allocator = new SignerVerificationAllocator(signer);
  }

  function test_Initialization() public {
    assertEq(allocator.signer(), signer);
    assertEq(allocator.owner(), owner);
  }

  function test_SetSigner() public {
    address newSigner = makeAddr("newSigner");

    vm.prank(owner);
    allocator.setSigner(newSigner);
    assertEq(allocator.signer(), newSigner);
  }

  function test_SetSigner_NotOwner() public {
    address newSigner = makeAddr("newSigner");

    vm.prank(other);
    vm.expectRevert("Ownable: caller is not the owner");
    allocator.setSigner(newSigner);
  }

  function test_TransferOwnership() public {
    address newOwner = makeAddr("newOwner");

    vm.prank(owner);
    allocator.transferOwnership(newOwner);
    assertEq(allocator.owner(), newOwner);

    // Old owner should fail
    vm.prank(owner);
    vm.expectRevert("Ownable: caller is not the owner");
    allocator.setSigner(signer);

    // New owner should succeed
    vm.prank(newOwner);
    allocator.setSigner(signer);
  }

  function test_authorizeClaim_ValidSignature() public {
    bytes32 claimHash = keccak256("claim");
    bytes32 digest = keccak256(
      abi.encodePacked(bytes2(0x1901), COMPACT_DOMAIN_SEPARATOR, claimHash)
    );

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
    bytes memory signature = abi.encodePacked(r, s, v);

    bool authorized = allocator.isClaimAuthorized(
      claimHash,
      address(0),
      address(0),
      0,
      0,
      new uint256[2][](0),
      signature
    );
    assertTrue(authorized);

    bytes4 selector = allocator.authorizeClaim(
      claimHash,
      address(0),
      address(0),
      0,
      0,
      new uint256[2][](0),
      signature
    );
    assertEq(selector, allocator.authorizeClaim.selector);
  }

  function test_authorizeClaim_InvalidSignature() public {
    bytes32 claimHash = keccak256("claim");
    bytes32 digest = keccak256(
      abi.encodePacked(bytes2(0x1901), COMPACT_DOMAIN_SEPARATOR, claimHash)
    );

    (, uint256 otherPk) = makeAddrAndKey("otherSigner");

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(otherPk, digest);
    bytes memory signature = abi.encodePacked(r, s, v);

    assertFalse(
      allocator.isClaimAuthorized(
        claimHash,
        address(0),
        address(0),
        0,
        0,
        new uint256[2][](0),
        signature
      )
    );

    vm.expectRevert("Invalid Sig");
    allocator.authorizeClaim(
      claimHash,
      address(0),
      address(0),
      0,
      0,
      new uint256[2][](0),
      signature
    );
  }

  function test_authorizeClaim_UpdateSigner() public {
    bytes32 claimHash = keccak256("claim");
    bytes32 digest = keccak256(
      abi.encodePacked(bytes2(0x1901), COMPACT_DOMAIN_SEPARATOR, claimHash)
    );

    (address newSigner, uint256 newPk) = makeAddrAndKey("newSigner");
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(newPk, digest);
    bytes memory signature = abi.encodePacked(r, s, v);

    assertFalse(
      allocator.isClaimAuthorized(
        claimHash,
        address(0),
        address(0),
        0,
        0,
        new uint256[2][](0),
        signature
      )
    );

    vm.prank(owner);
    allocator.setSigner(newSigner);

    assertTrue(
      allocator.isClaimAuthorized(
        claimHash,
        address(0),
        address(0),
        0,
        0,
        new uint256[2][](0),
        signature
      )
    );
  }
}
