// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

library BytesLib {
    /// @notice Helper function to convert Big Endian 16 bytes Data To Little Endian or vice versa
    function betole_16(bytes16 a) internal pure returns (bytes16) {
        bytes16 b;
        for (uint256 i; i < 16; i++) {
            bytes1 c = bytes1(a << (i * 8) & bytes1(0xff));
            b = b >> 8 | c;
        }
        return b;
    }

    /// @notice Helper function to convert Big Endian 8 bytes Data To Little Endian or vice versa
    function betole_8(bytes8 a) internal pure returns (bytes8) {
        bytes8 b;
        for (uint256 i; i < 8; i++) {
            bytes1 c = bytes1(a << (i * 8) & bytes1(0xff));
            b = b >> 8 | c;
        }
        return b;
    }

    /// @notice Helper function to convert Big Endian 4 bytes Data To Little Endian or vice versa
    function betole_4(bytes4 a) internal pure returns (bytes4) {
        bytes4 b;
        for (uint256 i; i < 4; i++) {
            bytes1 c = bytes1(a << (i * 8) & bytes1(0xff));
            b = b >> 8 | c;
        }
        return b;
    }

    /// @notice Helper function to convert Big Endian 2 bytes Data To Little Endian or vice versa
    function betole_2(bytes2 a) internal pure returns (bytes2) {
        bytes2 b;
        for (uint256 i; i < 2; i++) {
            bytes1 c = bytes1(a << (i * 8) & bytes1(0xff));
            b = b >> 8 | c;
        }
        return b;
    }
}
