// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

library  EnumerableSetRing {

    struct EnumerableSetRing {
        bytes32[] list;
        uint256 position;
        mapping(bytes32 key => uint256 position) map;
    }

    uint256 public constant MAX_BUFFER_SIZE = 1000;

    /**
     * @dev Adds a key-value pair to a Set, or updates the value for an existing
     * key. O(1).
     *
     * For Vector The operation old_value -> 0 then 0 -> new_value will be more gas consuming than old_value -> new_value.
     * Returns true if the key was added to the Set, that is if it was not
     * already present.
     */
    function set(EnumerableSetRing storage set, bytes32 value) internal returns (bool) {
        if(!contains(set,value)) {
            uint256 position = set.position;
            if (set.list.length == MAX_BUFFER_SIZE) {
                bytes32 old_value = set.list[position];
                delete set.map[old_value];
                set.list[position] = value;
            } else {
                set.list.push(value);
            }
            set.map[value] = position;
            set.position = ++set.position % MAX_BUFFER_SIZE;
            return true;
        }
        else {
            return false;
        }
    }

    /**
     * @dev Returns true if the key is in the set. O(1).
     */
    function contains(EnumerableSetRing storage set, bytes32 key) internal view returns (bool) {
        if(set.list.length == 0) {
            return false;
        }
        uint256 position = set.map[key];
        return (set.list[position] == key);
    }

    /**
     * @dev Return the an array containing all the keys
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(EnumerableSetRing storage set) internal view returns (bytes32[] memory) {
        return set.list;
    }

    function capacity(EnumerableSetRing storage set) internal view returns (uint256) {
        return values(set).length;
    }
}
