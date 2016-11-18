#!/usr/bin/env python

import unittest

from collections import namedtuple

from ct.crypto import in_memory_merkle_tree
from ct.crypto import merkle

PathTestVector = namedtuple('PathTestVector',
    ['leaf', 'tree_size_snapshot', 'path_length', 'path'])

ConsistencyTestVector = namedtuple('ConsistencyTestVector',
    ['snapshot_1', 'snapshot_2', 'proof'])

DummySTH = namedtuple('DummySTH', ['tree_size', 'sha256_root_hash'])

# Leaves of a sample tree of size 8.
test_vector_data = [t.decode('hex') for t in [
    "",
    "00",
    "10",
    "2021",
    "3031",
    "40414243",
    "5051525354555657",
    "606162636465666768696a6b6c6d6e6f",
    ]]

#TODO: DecodeHexStringsList

precomputed_path_test_vectors = [
    PathTestVector(0, 0, 0, []),
    PathTestVector(0, 1, 0, []),
    PathTestVector(0, 8, 3,
        [t.decode('hex') for t in [
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"]]),
    PathTestVector(5, 8, 3,
        [t.decode('hex') for t in [
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"]]),
    PathTestVector(2, 3, 1,
        ["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125".decode('hex')]),
    PathTestVector(1, 5, 3,
        [t.decode('hex') for t in [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"]]),
        ]

precomputed_proof_test_vectors = [
    ConsistencyTestVector(1, 1, []),
    ConsistencyTestVector(1, 8,
        [t.decode('hex') for t in [
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"
            ]]),
    ConsistencyTestVector(6, 8,
        [t.decode('hex') for t in [
            "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"
            ]]),
    ConsistencyTestVector(2, 5,
        [t.decode('hex') for t in [
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"
            ]]),
    ]

class InMemoryMerkleTreeTest(unittest.TestCase):
    def test_tree_incremental_root_hash(self):
        tree = in_memory_merkle_tree.InMemoryMerkleTree([])
        hasher = merkle.TreeHasher()
        for i in range(len(test_vector_data)):
          tree.add_leaf(test_vector_data[i])
          self.assertEqual(
              tree.get_root_hash(), hasher.hash_full_tree(test_vector_data[0:i+1]))

    def test_tree_snapshot_root_hash(self):
        tree = in_memory_merkle_tree.InMemoryMerkleTree(test_vector_data)
        hasher = merkle.TreeHasher()
        for i in range(len(test_vector_data)):
            self.assertEqual(
                    tree.get_root_hash(i), hasher.hash_full_tree(test_vector_data[0:i]))

    def test_tree_inclusion_proof_precomputed(self):
        tree = in_memory_merkle_tree.InMemoryMerkleTree(test_vector_data)
        verifier = merkle.MerkleVerifier()
        for v in precomputed_path_test_vectors:
            audit_path = tree.get_inclusion_proof(v.leaf, v.tree_size_snapshot)
            self.assertEqual(len(audit_path), v.path_length)
            self.assertEqual(audit_path, v.path)

            leaf_data = test_vector_data[v.leaf]
            leaf_hash = merkle.TreeHasher().hash_leaf(leaf_data)
            dummy_sth = DummySTH(v.tree_size_snapshot,
                tree.get_root_hash(v.tree_size_snapshot))

            if (v.tree_size_snapshot > 0):
              verifier.verify_leaf_hash_inclusion(leaf_hash, v.leaf, audit_path, dummy_sth)

    def test_tree_inclusion_proof_generated(self):
        leaves = []
        leaf_hashes = []
        hasher = merkle.TreeHasher()
        for i in range(128):
          leaves.append(chr(i) * 32)
          leaf_hashes.append(hasher.hash_leaf(leaves[-1]))

        tree = in_memory_merkle_tree.InMemoryMerkleTree(leaves)
        verifier = merkle.MerkleVerifier()

        for i in range(1, tree.tree_size()):
          for j in range(i):
            audit_path = tree.get_inclusion_proof(j, i)
            dummy_sth = DummySTH(i, tree.get_root_hash(i))
            verifier.verify_leaf_hash_inclusion(leaf_hashes[j], j, audit_path, dummy_sth)

    def test_tree_consistency_proof_precomputed(self):
        tree = in_memory_merkle_tree.InMemoryMerkleTree(test_vector_data)
        for v in precomputed_proof_test_vectors:
            consistency_proof = tree.get_consistency_proof(v.snapshot_1, v.snapshot_2)
            self.assertEqual(consistency_proof, v.proof)

    def test_tree_consistency_proof_generated(self):
        leaves = []
        for i in range(128):
          leaves.append(chr(i) * 32)

        tree = in_memory_merkle_tree.InMemoryMerkleTree(leaves)
        verifier = merkle.MerkleVerifier()

        for i in range(1, tree.tree_size()):
          for j in range(i):
              consistency_proof = tree.get_consistency_proof(j, i)
              self.assertTrue(verifier.verify_tree_consistency(j, i,
                  tree.get_root_hash(j), tree.get_root_hash(i), consistency_proof))

    #TODO: InMemoryMerkleTree tests for: too large leaf index, tree size
    #TODO: Consistency between usage of ' and "

if __name__ == "__main__":
    unittest.main()
