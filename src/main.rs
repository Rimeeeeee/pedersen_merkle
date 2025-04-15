use transaction::transactions::{Transaction, TransactionLedger};
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::Rng;
use std::env;
use std::str::FromStr;
mod merkle;
mod pedersen;
mod transaction;
//helper fxn to create test commitments for merkle tree
fn create_test_commitments_for_merkle_tree(count: usize) -> Vec<RistrettoPoint> {
    let pc = pedersen::pedersen_commitment::PedersenCommitment::new();
    let mut rng = rand::rng();
    (0..count)
        .map(|_i| {
            let blinding = pc.random_blinding();
            let random_value = rng.random_range(0..u64::MAX) as u64;
            pc.commit(random_value, &blinding)
        })
        .collect()
}
//helper fxn to create test commitments for transaction
fn create_test_commitments_for_transaction(count:usize)->Vec<Transaction>{
    
    let mut rng = rand::rng();
    (0..count)
        .map(|_i| {
            
            let random_value = rng.random_range(0..u64::MAX) as u64;
            Transaction::new(random_value)
        })
        .collect()
}


fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <demo> [inputs...]", args[0]);
        eprintln!("Available demos: pedersen <value>, merkle <count>, ledger <count> <value>");
        return;
    }

    let demo = args[1].as_str();

    match demo {
        //EXAMPLE_USAGE: cargo run --pedersen 42
        "pedersen" => {
            if args.len() < 3 {
                eprintln!("Usage: {} pedersen <value>", args[0]);
                return;
            }
            let value = u64::from_str(&args[2]).expect("Invalid value");

            let pc = pedersen::pedersen_commitment::PedersenCommitment::new();
            let blinding = pc.random_blinding();
            println!("Blinding from pederson: {:?}", blinding);

            let commitment = pc.commit(value, &blinding);
            println!("Commitment from pederson: {:?}", commitment);
            let is_valid = pc.verify(&commitment, value, &blinding);
            println!("Is valid from pederson: {:?}", is_valid);
        }
        //EXAMPLE_USAGE: cargo run --merkle 320
        "merkle" => {
            if args.len() < 3 {
                eprintln!("Usage: {} merkle <count>", args[0]);
                return;
            }
            let count = usize::from_str(&args[2]).expect("Invalid count");

            let commitments = create_test_commitments_for_merkle_tree(count);
            let merkle_tree = merkle::merkle_tree::MerkleTree::new(commitments.clone());
            let root = merkle_tree.root_hash();
            let rt = hex::encode(&root);
            println!("Merkle Root from merkle: {:?}", root);
            println!("Merkle Root Hash from merkle: {:?}", rt);
        }
        //EXAMPLE_USAGE: cargo run --ledger 64 567
        "ledger" => {
            if args.len() < 4 {
                eprintln!("Usage: {} ledger <count> <value>", args[0]);
                return;
            }

            let count = usize::from_str(&args[2]).expect("Invalid count");
            let value = u64::from_str(&args[3]).expect("Invalid value");

            let tx1 = Transaction::new(42);
            let tx2 = Transaction::new(99);
            let ledger = TransactionLedger::new(vec![tx1.clone(), tx2.clone()]);
            println!("Initial Merkle Root Hash from ledger: {}", ledger.root_hash());

            let index = ledger.find_transaction(&tx2.commitment);
            println!("Tx2 is at index from ledger: {:?}", index);

            let mut txs = create_test_commitments_for_transaction(count);
            let r = Transaction::new(value);
            txs.push(r.clone());
            let x = TransactionLedger::new(txs);
            println!("Transaction Ledger for randomized values: {:?}", x.transactions);
            let root = x.root_hash();
            println!("Transaction Ledger Merkle Root Hash for randomized values: {}", root);
            let presence = x.find_transaction(&r.commitment);
            println!("Transaction is present in ledger: {:?}", presence);
        }

        _ => {
            eprintln!("Invalid demo choice. Use one of: pedersen, merkle, ledger");
        }
    }
}