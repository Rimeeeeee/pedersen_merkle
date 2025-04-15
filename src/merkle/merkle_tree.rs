use curve25519_dalek::ristretto::RistrettoPoint;
use sha2::{Digest, Sha512};

#[allow(unused_imports)]
use crate::pedersen::pedersen_commitment::PedersenCommitment;
#[derive(Debug, Clone)]
#[allow(dead_code)]
///this module implements the Merkle tree using Ristretto points as leaves.
/// the internal nodes are hashed utilizing the SHA512 hash function.
pub enum MerkleNode {
    /// Leaf node containing a Ristretto commitment
    Leaf(RistrettoPoint),
    Internal {
        /// Left child node
        left: Box<MerkleNode>,
        /// Right child node
        right: Box<MerkleNode>,
        /// Hash of the concatenated hashes of the left and right child nodes
        hash: [u8; 64],
    },
}
//// Represents a Merkle tree with a root node
pub struct MerkleTree {
    pub root: MerkleNode,
}

impl MerkleTree {
    /// Creates a Merkle tree from a list of Ristretto commitments
    pub fn new(leaves: Vec<RistrettoPoint>) -> Self {
        assert!(!leaves.is_empty(), "Leaf list cannot be empty");

        let leaf_nodes: Vec<MerkleNode> = leaves.into_iter().map(MerkleNode::Leaf).collect();

        let root = MerkleTree::build_tree(leaf_nodes);
        MerkleTree { root }
    }
    /// Builds the Merkle tree from the leaf nodes
    fn build_tree(mut nodes: Vec<MerkleNode>) -> MerkleNode {
        while nodes.len() > 1 {
            let mut parent_nodes = Vec::new();

            for pair in nodes.chunks(2) {
                let left = pair[0].clone();
                let right = if pair.len() == 2 {
                    pair[1].clone()
                } else {
                    pair[0].clone()
                };

                let combined_hash = MerkleTree::hash_nodes(&left, &right);
                parent_nodes.push(MerkleNode::Internal {
                    left: Box::new(left),
                    right: Box::new(right),
                    hash: combined_hash,
                });
            }

            nodes = parent_nodes;
        }

        nodes.remove(0)
    }
    /// Hashes two Merkle nodes and returns the resulting hash as a byte array
    fn hash_nodes(left: &MerkleNode, right: &MerkleNode) -> [u8; 64] {
        let l_bytes = MerkleTree::node_hash_bytes(left);
        let r_bytes = MerkleTree::node_hash_bytes(right);

        let mut hasher = Sha512::new();
        hasher.update(&l_bytes);
        hasher.update(&r_bytes);
        let hash_bytes = hasher.finalize();

        let mut hash_array = [0u8; 64];
        hash_array.copy_from_slice(&hash_bytes[..64]);
        hash_array
    }
    //// Returns the hash bytes of a Merkle node
    fn node_hash_bytes(node: &MerkleNode) -> Vec<u8> {
        match node {
            MerkleNode::Leaf(pt) => pt.compress().as_bytes().to_vec(),
            MerkleNode::Internal { hash, .. } => hash.to_vec(),
        }
    }

    /// Returns the Merkle root hash as SHA512 hash bytes
    pub fn root_hash(&self) -> [u8; 64] {
        match &self.root {
            MerkleNode::Internal { hash, .. } => *hash,
            MerkleNode::Leaf(pt) => {
                let mut hasher = Sha512::new();
                hasher.update(pt.compress().as_bytes());
                let hash_bytes = hasher.finalize();
                let mut hash_array = [0u8; 64];
                hash_array.copy_from_slice(&hash_bytes[..64]);
                hash_array
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use sha2::{Digest, Sha512};

    // Helper function to create test commitments
    fn create_test_commitments(count: usize) -> Vec<RistrettoPoint> {
        let pc = PedersenCommitment::new();
        (0..count)
            .map(|i| {
                let blinding = pc.random_blinding();
                pc.commit((i * 10) as u64, &blinding)
            })
            .collect()
    }

    #[test]
    fn test_merkle_tree_root_from_pedersen_commitments() {
        let commitments = create_test_commitments(5);
        let merkle_tree = MerkleTree::new(commitments.clone());
        let root = merkle_tree.root_hash();

        let merkle_tree2 = MerkleTree::new(commitments);
        let root2 = merkle_tree2.root_hash();

        assert_eq!(root, root2);
    }

    #[test]
    fn test_merkle_tree_with_single_commitment() {
        let commitments = create_test_commitments(1);
        let merkle_tree = MerkleTree::new(commitments.clone());
        let root = merkle_tree.root_hash();

        let mut hasher = Sha512::new();
        hasher.update(commitments[0].compress().as_bytes());
        let expected_hash = hasher.finalize();
        let mut expected_array = [0u8; 64];
        expected_array.copy_from_slice(&expected_hash[..64]);

        assert_eq!(root, expected_array);
    }

    #[test]
    fn test_merkle_tree_with_odd_number_of_commitments() {
        let commitments = create_test_commitments(3);
        let tree = MerkleTree::new(commitments.clone());
        let root = tree.root_hash();

        let tree2 = MerkleTree::new(commitments);
        assert_eq!(root, tree2.root_hash());
    }

    #[test]
    fn test_merkle_tree_root_changes_on_leaf_order_change() {
        let mut commitments = create_test_commitments(3);
        let root1 = MerkleTree::new(commitments.clone()).root_hash();

        commitments.swap(0, 1);
        let root2 = MerkleTree::new(commitments).root_hash();

        assert_ne!(root1, root2);
    }
}
