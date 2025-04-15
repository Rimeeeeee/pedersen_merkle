use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::TryRngCore;
use rand_core::OsRng;

use crate::merkle::merkle_tree::MerkleTree;
use crate::pedersen;
///this module is used for constructing a merkle tree using the Pedersen commitment scheme
/// it checks whether a particular commitment is present inside the merkle tree
#[derive(Debug, Clone)]
//// Represents a transaction with a Pedersen commitment
pub struct Transaction {
    pub commitment: RistrettoPoint,
}

impl Transaction {
    /// Creates a new transaction using a Pedersen commitment
    pub fn new(amount: u64) -> Self {
        let pc = pedersen::pedersen_commitment::PedersenCommitment::new();
        let mut rng = OsRng;
        let mut random_bytes = [0u8; 32];
        let _u = rng.try_fill_bytes(&mut random_bytes);
        let blinding = Scalar::from_bytes_mod_order(random_bytes);
        let commitment = pc.commit(amount, &blinding);

        Transaction { commitment }
    }
}

pub struct TransactionLedger {
    pub transactions: Vec<Transaction>,
    pub tree: MerkleTree,
}

impl TransactionLedger {
    /// Creates a new ledger from a list of transactions
    pub fn new(transactions: Vec<Transaction>) -> Self {
        let commitments = transactions.iter().map(|tx| tx.commitment).collect();
        let tree = MerkleTree::new(commitments);

        TransactionLedger { transactions, tree }
    }
    //// Returns the root hash of the Merkle tree as a hex string
    pub fn root_hash(&self) -> String {
        hex::encode(self.tree.root_hash())
    }
    ///checks whether a commitment is present in merkle tree
    pub fn find_transaction(&self, commitment: &RistrettoPoint) -> bool {
        let r = self
            .transactions
            .iter()
            .position(|tx| &tx.commitment == commitment);
        match r {
            Some(_) => true,
            None => false,
        }
    }
}
