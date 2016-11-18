"""In-memory Merkle Tree

Operates (and owns) an in-memory array of leaves which can be updated.
Not particularly efficient.
"""

import math

from ct.crypto import merkle

def _down_to_power_of_two(n):
    if n < 2:
        raise ValueError("N should be >= 2: %d" % n)
    log_n = math.log(n, 2)
    p = int(log_n)
    # If n is exactly power of 2 then 2**p would be n, decrease p by 1.
    if p == log_n:
        p = p - 1
    return 2**p

class InMemoryMerkleTree(object):
    """Start with the array of |leaves| provided."""
    def __init__(self, leaves):
        self.__leaves = list(leaves)
        self.__hasher = merkle.TreeHasher()

    """Returns an array of hashed leaves."""
    def _hashed_leaves(self):
        return [self.__hasher.hash_leaf(t) for t in self.__leaves]

    """Adds |leaf| to the tree, returning the index of the entry."""
    def add_leaf(self, leaf):
        self.__leaves.append(leaf)
        return len(self.__leaves) - 1

    def tree_size(self):
        return len(self.__leaves)

    """Returns the root hash of the tree or a subtree denoted by |tree_size|"""
    def get_root_hash(self, tree_size = None):
        if tree_size is None:
            tree_size = self.tree_size()
        return self.__hasher.hash_full_tree(self.__leaves[:tree_size])

    """Returns the index of the leaf hash, or -1 if not present."""
    def get_leaf_index(self, leaf_hash):
        leaf_hashes = [self.__hasher.hash_leaf(t) for t in self.__leaves]
        try:
            return self._hashed_leaves().index(leaf_hash)
        except ValueError as e:
            return -1

    def _calculate_subproof(self, m, leaves, complete_subtree):
        n = len(leaves)
        if m == n or n == 1:
            if complete_subtree:
                return []
            else:
                return [self.__hasher.hash_full_tree(leaves)]

        k = _down_to_power_of_two(n)
        if m <= k:
            node = self.__hasher.hash_full_tree(leaves[k:n])
            res = self._calculate_subproof(m, leaves[0:k], complete_subtree)
        else:
            # m > k
            node = self.__hasher.hash_full_tree(leaves[0:k])
            res = self._calculate_subproof(m - k, leaves[k:n], False)
        res.append(node)
        return res

    """Returns a consistency proof between two snapshots of the tree."""
    def get_consistency_proof(self, tree_size_1, tree_size_2 = None):
        if tree_size_2 is None:
            tree_size_2 = self.tree_size()

        if tree_size_1 > self.tree_size() or tree_size_2 > self.tree_size():
            raise ValueError("Requested proof for sizes beyond current tree:" 
                    " current tree: %d tree_size_1 %d tree_size_2 %d" % (
                        self.tree_size(), tree_size_1, tree_size_2))

        if tree_size_1 > tree_size_2:
            raise ValueError("tree_size_1 must be less than tree_size_2")
        if tree_size_1 == tree_size_2 or tree_size_1 == 0:
            return []

        return self._calculate_subproof(
                tree_size_1, self.__leaves[:tree_size_2], True)

    def _calculate_inclusion_proof(self, leaves, leaf_index):
        n = len(leaves)
        if n == 0 or n == 1:
            return []

        k = _down_to_power_of_two(n)
        m = leaf_index
        if m < k:
            mth_k_to_n = self.__hasher.hash_full_tree(leaves[k:n])
            path = self._calculate_inclusion_proof(leaves[0:k], m)
            path.append(mth_k_to_n)
        else:
            mth_0_to_k = self.__hasher.hash_full_tree(leaves[0:k])
            path = self._calculate_inclusion_proof(leaves[k:n], m - k)
            path.append(mth_0_to_k)
        return path

    def get_inclusion_proof(self, leaf_index, tree_size):
        if tree_size > self.tree_size():
            raise ValueError("Specified tree size is bigger than known tree: %d" %
                    tree_size)
        if leaf_index >= self.tree_size():
            raise ValueError("Requested proof for leaf beyond tree size: %d" %
                    leaf_index)

        return self._calculate_inclusion_proof(self.__leaves[:tree_size], leaf_index)

