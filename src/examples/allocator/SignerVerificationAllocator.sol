// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IAllocator} from "../../interfaces/IAllocator.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {
  Ownable
} from "lib/permit2/lib/openzeppelin-contracts/contracts/access/Ownable.sol";

contract SignerVerificationAllocator is IAllocator, Ownable {
  using SignatureCheckerLib for address;

  /// @dev EIP-712 domain typehash
  bytes32 internal constant _EIP_712_DOMAIN_TYPEHASH =
    0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

  /// @dev Name hash for EIP-712 domain
  bytes32 internal constant _NAME_HASH =
    0x5e6f7b4e1ac3d625bac418bc955510b3e054cb6cc23cc27885107f080180b292;

  /// @dev Version hash for EIP-712 domain
  bytes32 internal constant _VERSION_HASH =
    0x044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d;

  /// @dev Verifying contract address for EIP-712 domain
  address internal constant _VERIFYING_CONTRACT =
    0x00000000000000171ede64904551eeDF3C6C9788;

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

  /// @dev Generates the EIP-712 domain separator dynamically
  /// @return The domain separator hash
  function _getDomainSeparator() internal view returns (bytes32) {
    return
      keccak256(
        abi.encode(
          _EIP_712_DOMAIN_TYPEHASH,
          _NAME_HASH,
          _VERSION_HASH,
          block.chainid,
          _VERIFYING_CONTRACT
        )
      );
  }

  /// @notice Public getter for the domain separator (useful for testing and external verification)
  /// @return The domain separator hash
  function getDomainSeparator() external view returns (bytes32) {
    return _getDomainSeparator();
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

    // Construct the EIP-712 digest using dynamically generated domain separator
    bytes32 domainSeparator = _getDomainSeparator();
    bytes32 digest = keccak256(
      abi.encodePacked(bytes2(0x1901), domainSeparator, claimHash)
    );

    // Verify the signature against the stored signer
    return signer.isValidSignatureNow(digest, allocatorData);
  }
}
