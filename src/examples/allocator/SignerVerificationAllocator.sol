// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { IAllocator } from "../../interfaces/IAllocator.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

interface EIP712 {
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

contract SignerVerificationAllocator is IAllocator {
    using SignatureCheckerLib for address;

    address public signer;
    address public owner;
    EIP712 internal immutable COMPACT;

    event SignerUpdated(address indexed oldSigner, address indexed newSigner);
    event OwnerUpdated(address indexed oldOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(address _signer, address compact) {
        signer = _signer;
        owner = msg.sender;
        COMPACT = EIP712(compact);
    }

    function setSigner(address _newSigner) external onlyOwner {
        address oldSigner = signer;
        signer = _newSigner;
        emit SignerUpdated(oldSigner, _newSigner);
    }

    function setOwner(address _newOwner) external onlyOwner {
        address oldOwner = owner;
        owner = _newOwner;
        emit OwnerUpdated(oldOwner, _newOwner);
    }

    function attest(address, address, address, uint256, uint256) external pure returns (bytes4) {
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
            isClaimAuthorized(claimHash, arbiter, sponsor, nonce, expires, idsAndAmounts, allocatorData), "Invalid Sig"
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
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), COMPACT.DOMAIN_SEPARATOR(), claimHash));

        // Verify the signature against the stored signer
        return signer.isValidSignatureNow(digest, allocatorData);
    }
}
