// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

import "./SupraErrors.sol";
import "./Smr.sol";
import "./BytesLib.sol";
import {ISupraSValueFeed} from "./ISupraSValueFeed.sol";
import {ISupraSValueFeedVerifier} from "./ISupraSValueFeedVerifier.sol";
import {UUPSUpgradeable} from "../lib/openzeppelin-contracts/contracts/proxy/utils/UUPSUpgradeable.sol";
import {MerkleProof} from "../lib/openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";
import {EnumerableSetRing} from "./EnumerableSetRing.sol";
import "../lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import {Ownable2StepUpgradeable} from "../lib/openzeppelin-contracts-upgradeable/contracts/access/Ownable2StepUpgradeable.sol";


/// @title Supra Oracle Pull Model Contract
/// @notice This contract verifies DORA committee Price feeds and returns the price data to the caller
/// @notice The contract does not make assumptions about its owner, but its recommended to be a multisig wallet
contract SupraOraclePull is  UUPSUpgradeable, Ownable2StepUpgradeable {
    using EnumerableSetRing for EnumerableSetRing.EnumerableSetRing;
    /// @notice Push Based Supra Svalue Feed Storage contract
    /// @dev This is used to check if a pair is stale

    ISupraSValueFeed internal supraSValueFeedStorage;
    ISupraSValueFeedVerifier internal supraSValueVerifier;
    // Max Future time is 3sec from the current block time.
    uint256 public constant TIME_DELTA_ALLOWANCE = 15000;
    /// Conversion factor between millisecond and second
    uint256 public constant MILLISECOND_CONVERSION_FACTOR = 1000;
    EnumerableSetRing.EnumerableSetRing private merkleSet;

    event SupraSValueFeedUpdated(address supraSValueFeedStorage);
    event SupraSValueVerifierUpdated(address supraSValueVerifier);
    event PriceUpdate(uint256[] pairs, uint256[] prices, uint256[] updateMask);

    /// @notice Price Pair Feed From Oracle Committee
    struct CommitteeFeed {
        uint32 pair;
        uint128 price;
        uint64 timestamp;
        uint16 decimals;
        uint64 round;
    }

    /// @notice Oracle Committee Pair Price Feed with Merkle proofs of the pair
    struct CommitteeFeedWithProof {
        CommitteeFeed[] committee_feeds;
        bytes32[] proofs;
        bool[] flags;
    }

    /// @notice Multiple Pair Price with Merkle Proof along with Committee details
    struct PriceDetailsWithCommittee {
        uint64 committee_id;
        bytes32 root;
        // DORA committee signature on the merkle root
        uint256[2] sigs;
        CommitteeFeedWithProof committee_data;
    }

    /// @notice Proof for verifying and extracting pairs from DORA committee feeds for Multiple Committees
    struct OracleProofV2 {
        PriceDetailsWithCommittee[] data;
    }

    /// @notice Verified price data
    struct PriceData {
        // List of pairs
        uint256[] pairs;
        // List of prices
        // prices[i] is the price of pairs[i]
        uint256[] prices;
        // List of decimals
        // decimals[i] is the decimals of pairs[i]
        uint256[] decimal;
    }

    /// @notice Verified price data
    struct PriceInfo {
        // List of pairs
        uint256[] pairs;
        // List of prices
        // prices[i] is the price of pairs[i]
        uint256[] prices;
        // List of timestamp
        // timestamp[i] is the timestamp of pairs[i]
        uint256[] timestamp;
        // List of decimals
        // decimals[i] is the decimals of pairs[i]
        uint256[] decimal;
        // List of round
        // round[i] is the round of pairs[i]
        uint256[] round;
    }

    /// @dev disabling the initializers only for the implementaion contract
    constructor() {
        _disableInitializers();
    }


    /// @notice Helper function for upgradeability
    /// @dev While upgrading using UUPS proxy interface, when we call upgradeTo(address) function
    /// @dev we need to check that only owner can upgrade
    /// @param newImplementation address of the new implementation contract
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {}

    function initialize(address _supraSValueFeedStorage, address _supraSValueVerifier) public initializer {
        Ownable2StepUpgradeable.__Ownable2Step_init();
        _updateSupraSValueFeedInitLevel(ISupraSValueFeed(_supraSValueFeedStorage));
        _updateSupraSValueVerifierInitLevel(ISupraSValueFeedVerifier(_supraSValueVerifier));
    }

    /// @notice Verify Oracle Pairs
    /// @dev throws error if proof is invalid
    /// @dev Stale price data is marked
    /// @param _bytesProof The oracle proof to extract the pairs from
    function verifyOracleProof(bytes calldata _bytesProof) external returns (PriceData memory) {
        OracleProofV2 memory oracle = abi.decode(_bytesProof, (OracleProofV2));
        uint256 paircnt;
        for (uint256 i; i < oracle.data.length; ++i) {
            paircnt += oracle.data[i].committee_data.committee_feeds.length;
            if (merkleSet.contains(oracle.data[i].root)) {
                continue;
            }
            requireRootVerified(oracle.data[i].root, oracle.data[i].sigs, oracle.data[i].committee_id);
            if (!merkleSet.set(oracle.data[i].root)) {
                revert RootIsZero();
            }
        }

        uint256[] memory updateMask = new uint256[](paircnt);

        PriceData memory priceData = PriceData(new uint256[](paircnt), new uint256[](paircnt), new uint256[](paircnt));

        uint256 pair_map = 0;
        uint256 maxFutureTimestamp = block.timestamp * MILLISECOND_CONVERSION_FACTOR + TIME_DELTA_ALLOWANCE;

        for (uint256 a = 0; a < oracle.data.length;) {
            verifyMultileafMerkleProof(oracle.data[a].committee_data, oracle.data[a].root);
            for (uint256 b = 0; b < oracle.data[a].committee_data.committee_feeds.length;) {

                priceData.pairs[pair_map] = oracle.data[a].committee_data.committee_feeds[b].pair;

                uint256 lastRound =
                    supraSValueFeedStorage.getRound(uint256(oracle.data[a].committee_data.committee_feeds[b].pair));
                if (
                    oracle.data[a].committee_data.committee_feeds[b].round > lastRound
                        && oracle.data[a].committee_data.committee_feeds[b].round <= maxFutureTimestamp
                ) {
                    packData(
                        oracle.data[a].committee_data.committee_feeds[b].pair,
                        oracle.data[a].committee_data.committee_feeds[b].round,
                        oracle.data[a].committee_data.committee_feeds[b].decimals,
                        oracle.data[a].committee_data.committee_feeds[b].timestamp,
                        oracle.data[a].committee_data.committee_feeds[b].price
                    );
                    priceData.prices[pair_map] = oracle.data[a].committee_data.committee_feeds[b].price;
                    priceData.decimal[pair_map] = oracle.data[a].committee_data.committee_feeds[b].decimals;
                    updateMask[pair_map] = 1;
                } else if (oracle.data[a].committee_data.committee_feeds[b].round > maxFutureTimestamp) {
                    revert IncorrectFutureUpdate(
                        oracle.data[a].committee_data.committee_feeds[b].round - block.timestamp * MILLISECOND_CONVERSION_FACTOR
                    );
                } else if (oracle.data[a].committee_data.committee_feeds[b].round < lastRound) {
                    ISupraSValueFeed.priceFeed memory value =
                        supraSValueFeedStorage.getSvalue(uint256(oracle.data[a].committee_data.committee_feeds[b].pair));
                    priceData.prices[pair_map] = value.price;
                    priceData.decimal[pair_map] = value.decimals;
                    updateMask[pair_map] = 0;
                } else {
                    priceData.prices[pair_map] = oracle.data[a].committee_data.committee_feeds[b].price;
                    priceData.decimal[pair_map] = oracle.data[a].committee_data.committee_feeds[b].decimals;
                    updateMask[pair_map] = 0;
                }

                unchecked {
                    ++b;
                    ++pair_map;
                }
            }

            unchecked {
                ++a;
            }
        }

        emit PriceUpdate(priceData.pairs, priceData.prices, updateMask);
        return priceData;
    }

    /// @notice Verify Oracle Pairs
    /// @dev throws error if proof is invalid
    /// @dev Stale price data is marked
    /// @param _bytesProof The oracle proof to extract the pairs from
    function verifyOracleProofV2(bytes calldata _bytesProof) external returns (PriceInfo memory) {
        OracleProofV2 memory oracle = abi.decode(_bytesProof, (OracleProofV2));
        uint256 paircnt = 0;
        for (uint256 i; i < oracle.data.length; ++i) {
            paircnt += oracle.data[i].committee_data.committee_feeds.length;
            if (merkleSet.contains(oracle.data[i].root)) {
                continue;
            }
            requireRootVerified(oracle.data[i].root, oracle.data[i].sigs, oracle.data[i].committee_id);
            if (!merkleSet.set(oracle.data[i].root)) {
                revert RootIsZero();
            }
        }

        uint256[] memory updateMask = new uint256[](paircnt);

        PriceInfo memory priceData = PriceInfo(
            new uint256[](paircnt),
            new uint256[](paircnt),
            new uint256[](paircnt),
            new uint256[](paircnt),
            new uint256[](paircnt)
        );

        uint256 pair_map = 0;
        uint256 maxFutureTimestamp = block.timestamp * MILLISECOND_CONVERSION_FACTOR + TIME_DELTA_ALLOWANCE;

        for (uint256 a = 0; a < oracle.data.length;) {
            verifyMultileafMerkleProof(oracle.data[a].committee_data, oracle.data[a].root);
            for (uint256 b = 0; b < oracle.data[a].committee_data.committee_feeds.length;) {
                priceData.pairs[pair_map] = oracle.data[a].committee_data.committee_feeds[b].pair;

                uint256 lastRound =
                                    supraSValueFeedStorage.getRound(uint256(oracle.data[a].committee_data.committee_feeds[b].pair));

                if (
                    oracle.data[a].committee_data.committee_feeds[b].round > lastRound
                    && oracle.data[a].committee_data.committee_feeds[b].round <= maxFutureTimestamp
                ) {
                    packData(
                        oracle.data[a].committee_data.committee_feeds[b].pair,
                        oracle.data[a].committee_data.committee_feeds[b].round,
                        oracle.data[a].committee_data.committee_feeds[b].decimals,
                        oracle.data[a].committee_data.committee_feeds[b].timestamp,
                        oracle.data[a].committee_data.committee_feeds[b].price
                    );
                    priceData.prices[pair_map] = oracle.data[a].committee_data.committee_feeds[b].price;
                    priceData.round[pair_map] = oracle.data[a].committee_data.committee_feeds[b].round;
                    priceData.timestamp[pair_map] = oracle.data[a].committee_data.committee_feeds[b].timestamp;
                    priceData.decimal[pair_map] = oracle.data[a].committee_data.committee_feeds[b].decimals;
                    updateMask[pair_map] = 1;
                } else if (oracle.data[a].committee_data.committee_feeds[b].round > maxFutureTimestamp) {
                    revert IncorrectFutureUpdate(
                        oracle.data[a].committee_data.committee_feeds[b].round - block.timestamp * MILLISECOND_CONVERSION_FACTOR
                    );
                } else if (oracle.data[a].committee_data.committee_feeds[b].round < lastRound) {
                    ISupraSValueFeed.priceFeed memory value =
                                        supraSValueFeedStorage.getSvalue(uint256(oracle.data[a].committee_data.committee_feeds[b].pair));
                    priceData.prices[pair_map] = value.price;
                    priceData.round[pair_map] = lastRound;
                    priceData.timestamp[pair_map] = value.time;
                    priceData.decimal[pair_map] = value.decimals;
                    updateMask[pair_map] = 0;
                } else {
                    priceData.prices[pair_map] = oracle.data[a].committee_data.committee_feeds[b].price;
                    priceData.round[pair_map] = oracle.data[a].committee_data.committee_feeds[b].round;
                    priceData.timestamp[pair_map] = oracle.data[a].committee_data.committee_feeds[b].timestamp;
                    priceData.decimal[pair_map] = oracle.data[a].committee_data.committee_feeds[b].decimals;
                    updateMask[pair_map] = 0;
                }

                unchecked {
                    ++b;
                    ++pair_map;
                }
            }

            unchecked {
                ++a;
            }
        }

        emit PriceUpdate(priceData.pairs, priceData.prices, updateMask);
        return priceData;
    }


    /// @notice Verify Oracle Pairs
    /// @dev throws error if proof is invalid
    /// @dev Stale price data is marked
    /// @param oracle The oracle proof to extract the pairs from
    function verifyOracleProofV2(OracleProofV2 calldata oracle) public returns (PriceInfo memory) {
        uint256 paircnt = 0;
        for (uint256 i; i < oracle.data.length; ++i) {
            paircnt += oracle.data[i].committee_data.committee_feeds.length;
            if (merkleSet.contains(oracle.data[i].root)) {
                continue;
            }
            requireRootVerified(oracle.data[i].root, oracle.data[i].sigs, oracle.data[i].committee_id);
            if (!merkleSet.set(oracle.data[i].root)) {
                revert RootIsZero();
            }
        }

        uint256[] memory updateMask = new uint256[](paircnt);

        PriceInfo memory priceData = PriceInfo(
            new uint256[](paircnt),
            new uint256[](paircnt),
            new uint256[](paircnt),
            new uint256[](paircnt),
            new uint256[](paircnt)
        );

        uint256 pair_map = 0;
        uint256 maxFutureTimestamp = block.timestamp * MILLISECOND_CONVERSION_FACTOR + TIME_DELTA_ALLOWANCE;

        for (uint256 a = 0; a < oracle.data.length;) {
            verifyMultileafMerkleProof(oracle.data[a].committee_data, oracle.data[a].root);
            for (uint256 b = 0; b < oracle.data[a].committee_data.committee_feeds.length;) {
                priceData.pairs[pair_map] = oracle.data[a].committee_data.committee_feeds[b].pair;

                uint256 lastRound =
                                    supraSValueFeedStorage.getRound(uint256(oracle.data[a].committee_data.committee_feeds[b].pair));

                if (
                    oracle.data[a].committee_data.committee_feeds[b].round > lastRound
                    && oracle.data[a].committee_data.committee_feeds[b].round <= maxFutureTimestamp
                ) {
                    packData(
                        oracle.data[a].committee_data.committee_feeds[b].pair,
                        oracle.data[a].committee_data.committee_feeds[b].round,
                        oracle.data[a].committee_data.committee_feeds[b].decimals,
                        oracle.data[a].committee_data.committee_feeds[b].timestamp,
                        oracle.data[a].committee_data.committee_feeds[b].price
                    );
                    priceData.prices[pair_map] = oracle.data[a].committee_data.committee_feeds[b].price;
                    priceData.round[pair_map] = oracle.data[a].committee_data.committee_feeds[b].round;
                    priceData.timestamp[pair_map] = oracle.data[a].committee_data.committee_feeds[b].timestamp;
                    priceData.decimal[pair_map] = oracle.data[a].committee_data.committee_feeds[b].decimals;
                    updateMask[pair_map] = 1;
                } else if (oracle.data[a].committee_data.committee_feeds[b].round > maxFutureTimestamp) {
                    revert IncorrectFutureUpdate(
                        oracle.data[a].committee_data.committee_feeds[b].round - block.timestamp * MILLISECOND_CONVERSION_FACTOR
                    );
                } else if (oracle.data[a].committee_data.committee_feeds[b].round < lastRound) {
                    ISupraSValueFeed.priceFeed memory value =
                                        supraSValueFeedStorage.getSvalue(uint256(oracle.data[a].committee_data.committee_feeds[b].pair));
                    priceData.prices[pair_map] = value.price;
                    priceData.round[pair_map] = lastRound;
                    priceData.timestamp[pair_map] = value.time;
                    priceData.decimal[pair_map] = value.decimals;
                    updateMask[pair_map] = 0;
                } else {
                    priceData.prices[pair_map] = oracle.data[a].committee_data.committee_feeds[b].price;
                    priceData.round[pair_map] = oracle.data[a].committee_data.committee_feeds[b].round;
                    priceData.timestamp[pair_map] = oracle.data[a].committee_data.committee_feeds[b].timestamp;
                    priceData.decimal[pair_map] = oracle.data[a].committee_data.committee_feeds[b].decimals;
                    updateMask[pair_map] = 0;
                }

                unchecked {
                    ++b;
                    ++pair_map;
                }
            }

            unchecked {
                ++a;
            }
        }

        emit PriceUpdate(priceData.pairs, priceData.prices, updateMask);
        return priceData;
    }

    /// @notice It helps to pack many data points into one single word (32 bytes)
    /// @dev This function will take the required parameters, Will shift the value to its specific position
    /// @dev For concatenating one value with another we are using unary OR operator
    /// @dev Saving the Packed data into the SupraStorage Contract
    /// @param _pair Pair identifier of the token pair
    /// @param _round Round on which DORA nodes collects and post the pair data
    /// @param _decimals Number of decimals that the price of the pair supports
    /// @param _price Price of the pair
    /// @param _time Last updated timestamp of the pair
    function packData(uint256 _pair, uint256 _round, uint256 _decimals, uint256 _time, uint256 _price) internal {
        uint256 r = uint256(_round) << 192;
        r = r | _decimals << 184;
        r = r | _time << 120;
        r = r | _price << 24;
        supraSValueFeedStorage.restrictedSetSupraStorage(_pair, bytes32(r));
    }

    /// @notice helper function to verify the multileaf merkle proof with the root
    function verifyMultileafMerkleProof(CommitteeFeedWithProof memory oracle, bytes32 root) private pure {
        bytes32[] memory leaf_hashes = new bytes32[](oracle.committee_feeds.length);
        bytes4 pair_le;
        bytes16 price_le;
        bytes8 timestamp_le;
        bytes2 decimals_le;
        bytes8 round_le;
        for (uint256 i = 0; i < oracle.committee_feeds.length; i++) {
            pair_le = BytesLib.betole_4(bytes4(abi.encodePacked(oracle.committee_feeds[i].pair)));
            price_le = BytesLib.betole_16(bytes16(abi.encodePacked(oracle.committee_feeds[i].price)));
            timestamp_le = BytesLib.betole_8(bytes8(abi.encodePacked(oracle.committee_feeds[i].timestamp)));
            decimals_le = BytesLib.betole_2(bytes2(abi.encodePacked(oracle.committee_feeds[i].decimals)));
            round_le = BytesLib.betole_8(bytes8(abi.encodePacked(oracle.committee_feeds[i].round)));
            leaf_hashes[i] = keccak256(abi.encodePacked(pair_le, price_le, timestamp_le, decimals_le, round_le));
        }
        if (MerkleProof.multiProofVerify(oracle.proofs,oracle.flags, root, leaf_hashes) == false) {
            revert InvalidProof();
        }
    }

    /// @notice Internal Function to check for zero address
    function _ensureNonZeroAddress(address contract_) private pure {
        if (contract_ == address(0)) {
            revert ZeroAddress();
        }
    }

    /// @notice Helper Function to update the supraSValueFeedStorage Contract address during contract initialization
    /// @param supraSValueFeed new supraSValueFeed
    function _updateSupraSValueFeedInitLevel(ISupraSValueFeed supraSValueFeed) private {
        _ensureNonZeroAddress(address(supraSValueFeed));
        supraSValueFeedStorage = supraSValueFeed;

        emit SupraSValueFeedUpdated(address(supraSValueFeed));
    }

    /// @notice Helper Function to update the supraSvalueVerifier Contract address during contract initialization
    /// @param supraSvalueVerifier new supraSvalueVerifier Contract address
    function _updateSupraSValueVerifierInitLevel(ISupraSValueFeedVerifier supraSvalueVerifier) private {
        _ensureNonZeroAddress(address(supraSvalueVerifier));
        supraSValueVerifier = supraSvalueVerifier;

        emit SupraSValueVerifierUpdated(address(supraSvalueVerifier));
    }

    /// @notice Helper Function to update the supraSValueFeedStorage Contract address in future
    /// @param supraSValueFeed new supraSValueFeedStorage Contract address
    function updateSupraSValueFeed(ISupraSValueFeed supraSValueFeed) external onlyOwner {
        _ensureNonZeroAddress(address(supraSValueFeed));
        supraSValueFeedStorage = supraSValueFeed;

        emit SupraSValueFeedUpdated(address(supraSValueFeed));
    }

    /// @notice Helper Function to check for the address of SupraSValueFeedVerifier contract
    function checkSupraSValueVerifier() external view returns (address) {
        return (address(supraSValueVerifier));
    }

    ///@notice Helper function to check for the address of SupraSValueFeed contract
    function checkSupraSValueFeed() external view returns (address) {
        return (address(supraSValueFeedStorage));
    }

    /// @notice Helper Function to update the supraSvalueVerifier Contract address in future
    /// @param supraSvalueVerifier new supraSvalueVerifier Contract address
    function updateSupraSValueVerifier(ISupraSValueFeedVerifier supraSvalueVerifier) external onlyOwner {
        _ensureNonZeroAddress(address(supraSvalueVerifier));
        supraSValueVerifier = supraSvalueVerifier;

        emit SupraSValueVerifierUpdated(address(supraSvalueVerifier));
    }

    /// @notice Verify root
    /// @dev Requires the provided votes to be verified using SupraSValueFeedVerifierContract contract's authority public key and BLS signature.
    /// @param root The root of the merkle tree created using the pair data
    /// @param sigs The BLS signature on the root of the merkle tree.
    /// @dev This function verifies the BLS signature by calling the SupraSValueFeedVerifierContract that uses BLS precompile contract and checks if the root matches the provided signature.
    /// @dev If the signature verification fails or if there is an issue with the BLS precompile contract call, the function reverts with an error.
    function requireRootVerified(bytes32 root, uint256[2] memory sigs, uint256 committee_id) internal view {
        (bool status,) = address(supraSValueVerifier).staticcall(
            abi.encodeCall(ISupraSValueFeedVerifier.requireHashVerified_V2, (root, sigs, committee_id))
        );
        if (!status) {
            revert DataNotVerified();
        }
    }
}
