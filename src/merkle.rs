//! RFC 9162 Merkle tree hashes.

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

/// RFC 9162 §2.1.1: the hash of an empty tree is the hash of the empty string
pub fn empty_root() -> Hash {
    Sha256::digest(b"").into()
}

pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0u8]);
    hasher.update(data);
    hasher.finalize().into()
}

pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([1u8]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Appends leaf hashes and yields the RFC 9162 tree hash after each append in O(log n).
#[derive(Debug, Default, Clone)]
pub struct MerkleAccumulator {
    pub size: usize,
    subtrees: Vec<(usize, Hash)>, // (leaf count, hash) of perfect subtrees, largest first
}

impl MerkleAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, leaf: Hash) {
        let (mut size, mut value) = (1, leaf);
        while let Some(&(last_size, left)) = self.subtrees.last() {
            if last_size != size {
                break;
            }
            self.subtrees.pop();
            value = node_hash(&left, &value);
            size *= 2;
        }
        self.subtrees.push((size, value));
        self.size += 1;
    }

    pub fn root(&self) -> Hash {
        let Some(&(_, last)) = self.subtrees.last() else {
            return empty_root();
        };
        // the perfect subtrees, combined right to left, are exactly the RFC's recursive split
        let mut value = last;
        for (_, left) in self.subtrees[..self.subtrees.len() - 1].iter().rev() {
            value = node_hash(left, &value);
        }
        value
    }
}

pub fn root<'a>(leaf_hashes: impl IntoIterator<Item = &'a Hash>) -> Hash {
    let mut accumulator = MerkleAccumulator::new();
    for leaf in leaf_hashes {
        accumulator.add(*leaf);
    }
    accumulator.root()
}

/// Parses a stored hex hash; malformed values (an edited row) become an all-zero hash, which never matches.
pub fn from_hex(text: &str) -> Hash {
    let mut hash = [0u8; 32];
    if hex::decode_to_slice(text, &mut hash).is_err() {
        return [0u8; 32];
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOTS: [&str; 8] = [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];

    fn leaves() -> Vec<Vec<u8>> {
        vec![
            vec![],
            vec![0x00],
            vec![0x10],
            vec![0x20, 0x21],
            vec![0x30, 0x31],
            vec![0x40, 0x41, 0x42, 0x43],
            (0x50..0x58).collect(),
            (0x60..0x70).collect(),
        ]
    }

    fn reference_root(hashes: &[Hash]) -> Hash {
        // RFC 9162 §2.1.1, literally: split at the largest power of two smaller than n
        match hashes.len() {
            0 => empty_root(),
            1 => hashes[0],
            n => {
                let mut k = 1;
                while k * 2 < n {
                    k *= 2;
                }
                node_hash(&reference_root(&hashes[..k]), &reference_root(&hashes[k..]))
            }
        }
    }

    #[test]
    fn rfc_test_vectors() {
        let hashes: Vec<Hash> = leaves().iter().map(|leaf| leaf_hash(leaf)).collect();
        for (size, expected) in ROOTS.iter().enumerate() {
            assert_eq!(hex::encode(root(&hashes[..size + 1])), *expected);
        }
    }

    #[test]
    fn empty_tree() {
        assert_eq!(root(&[]), empty_root());
        assert_eq!(MerkleAccumulator::new().root(), empty_root());
    }

    #[test]
    fn accumulator_matches_reference_after_every_append() {
        let hashes: Vec<Hash> = (0u32..70).map(|n| leaf_hash(&n.to_le_bytes())).collect();
        let mut accumulator = MerkleAccumulator::new();
        for (index, leaf) in hashes.iter().enumerate() {
            accumulator.add(*leaf);
            assert_eq!(accumulator.size, index + 1);
            assert_eq!(accumulator.root(), reference_root(&hashes[..index + 1]));
        }
    }
}
