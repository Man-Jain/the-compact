// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IAllocator} from "../../interfaces/IAllocator.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {
  Ownable
} from "lib/permit2/lib/openzeppelin-contracts/contracts/access/Ownable.sol";

contract SignerVerificationAllocator is IAllocator, Ownable {
  using SignatureCheckerLib for address;

  /// @dev Static Compact EIP-712 domain separator
  bytes32 internal constant COMPACT_DOMAIN_SEPARATOR =
    0x86e7aad2e0029bde18b0d57fc8f265574d4ff8cc5c8b859ed76df2428b57de53;

  address public signer;

  event SignerUpdated(address indexed oldSigner, address indexed newSigner);

  constructor(address _signer) Ownable() {
    signer = _signer;
  }

  function setSigner(address _newSigner) external onlyOwner {
    address oldSigner = signer;
    signer = _newSigner;
    emit SignerUpdated(oldSigner, _newSigner);
  }

  function attest(
    address,
    address,
    address,
    uint256,
    uint256
  ) external pure returns (bytes4) {
    revert("unimplemented");
  }

  function authorizeClaim(
    bytes32 claimHash,
    address arbiter,
    address sponsor,
    uint256 nonce,
    uint256 expires,
    uint256[2][] calldata idsAndAmounts,
    bytes calldata allocatorData
  ) external view returns (bytes4) {
    require(
      isClaimAuthorized(
        claimHash,
        arbiter,
        sponsor,
        nonce,
        expires,
        idsAndAmounts,
        allocatorData
      ),
      "Invalid Sig"
    );

    return this.authorizeClaim.selector;
  }

  function isClaimAuthorized(
    bytes32 claimHash,
    address arbiter,
    address sponsor,
    uint256 nonce,
    uint256 expires,
    uint256[2][] calldata idsAndAmounts,
    bytes calldata allocatorData
  ) public view returns (bool) {
    // Silence unused variable warnings
    arbiter;
    sponsor;
    nonce;
    expires;
    idsAndAmounts;

    // Construct the EIP-712 digest
    bytes32 digest = keccak256(
      abi.encodePacked(bytes2(0x1901), COMPACT_DOMAIN_SEPARATOR, claimHash)
    );

    // Verify the signature against the stored signer
    return signer.isValidSignatureNow(digest, allocatorData);
  }
}
