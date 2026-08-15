pragma solidity ^0.8.24;

interface ISupraSValueFeedVerifier {
    function isPairAlreadyAddedForHCC(uint256[] calldata _pairIndexes) external view returns (bool);

    function isPairAlreadyAddedForHCC(uint256 _pairId) external view returns (bool);

    function requireHashVerified_V2(bytes32 message, uint256[2] memory signature, uint256 committee_id) external view;

    function requireHashVerified_V1(bytes memory message, uint256[2] memory signature) external view;
}
