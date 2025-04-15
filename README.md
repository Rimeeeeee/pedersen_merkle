# Utlizing Pedersen Commitments In Merkle Tree Ledger

This Rust project demonstrates cryptographic building blocks including Pedersen commitments, Merkle trees, and a ledger system for anonymous transactions. It showcases how to create secure commitments, build Merkle trees from them, and track transactions in a verifiable and privacy-preserving way.

### How It Works:
- **Pedersen Commitment** is calculated using `g*v+h*blinding` where `g` is the base point, `v` is the value to commit, `h` is another base point with no discrete log relation with `g`, and `blinding` is a random number.
- **Merkle Tree** is constructed by hashing pairs of commitments using `SHA512`.Though at the base level is simple commitment of `RistrettoPoint`,the internal nodes are hashed using `SHA512`.
- **Ledger** is a data structure that stores transactions. Each transaction is a commitment to **Merkle Tree** under **Pedersen Commitment** thus masking the value.
---
## Features

- **Pedersen Commitments:** Secure and hiding commitments for numeric values using Curve25519 and the Ristretto group.
- **Merkle Trees:** Generate Merkle trees from commitments and compute root hashes.
- **Transaction Ledger:** Record transactions with cryptographic commitments and verify their presence using Merkle proofs.
---
## Cryptographic Primitives Used

- Curve25519 via [curve25519-dalek](https://docs.rs/curve25519-dalek)
- Ristretto group for eliminating subgroup attacks
- Pedersen commitments for binding and hiding value representation
- Merkle tree for scalable verification

---

## Advantages of Combining Pedersen Commitments with Merkle Trees

By combining Pedersen Commitments with Merkle Trees, this system achieves both **data privacy** and **efficient verification**:

1. **Hiding and Binding**:  
   Pedersen commitments allow values to be committed without revealing them, while also preventing modification.

2. **Zero-Knowledge Compatibility**:  
   The homomorphic properties of Pedersen commitments make them ideal for use in zero-knowledge proof systems, which can prove relationships about committed values without revealing them.

3. **Efficient Integrity Verification**:  
   Merkle trees enable verifying the inclusion of a specific commitment in a dataset with logarithmic complexity using a Merkle proof, without revealing the full dataset.

4. **Anonymity in Ledgers**:  
   Transactions can be tracked and validated without linking them to explicit values or identities.


---
### Test The Project:
To test the project just run:
```rust
cargo test
```
Moreover the output associated with this project can be found in `output.txt`,`merkle_tree_result.txt` and `pedersen_test_result.txt`.
