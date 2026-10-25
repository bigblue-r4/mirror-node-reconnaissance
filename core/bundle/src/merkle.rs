//! The log's Merkle tree: BLAKE3, the entry line's bytes as the leaf preimage.
//!
//! `leaf = BLAKE3(0x00 ‖ line)` and `node = BLAKE3(0x01 ‖ left ‖ right)`, with
//! the split at the largest power of two strictly smaller than the leaf count
//! (the RFC 6962 shape `merkle.Prove` uses). An audit path is returned
//! leaf-first: the innermost sibling is first and the root's sibling is last,
//! which is the order `tools/bundle-verify/verify_bundle.py` consumes.
//!
//! An empty log has the all-zero root and no leaves. That matches the verifier,
//! and it keeps a zero-entry bundle expressible without a special case in the
//! header.

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

pub(crate) fn leaf_hash(line: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(1 + line.len());
    preimage.push(LEAF_PREFIX);
    preimage.extend_from_slice(line);
    *blake3::hash(&preimage).as_bytes()
}

pub(crate) fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 65];
    preimage[0] = NODE_PREFIX;
    preimage[1..33].copy_from_slice(left);
    preimage[33..].copy_from_slice(right);
    *blake3::hash(&preimage).as_bytes()
}

/// Largest power of two strictly smaller than `n`, for `n > 1`.
fn split_point(n: usize) -> usize {
    debug_assert!(n > 1);
    n.next_power_of_two() >> 1
}

#[derive(Debug, Clone)]
pub(crate) struct Tree {
    root: Option<Node>,
}

#[derive(Debug, Clone)]
struct Node {
    hash: [u8; 32],
    count: usize,
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}

impl Tree {
    pub(crate) fn from_lines(lines: &[Vec<u8>]) -> Self {
        if lines.is_empty() {
            return Tree { root: None };
        }
        let leaves = lines
            .iter()
            .map(|line| Node {
                hash: leaf_hash(line),
                count: 1,
                left: None,
                right: None,
            })
            .collect();
        Tree {
            root: Some(build(leaves)),
        }
    }

    pub(crate) fn size(&self) -> usize {
        self.root.as_ref().map_or(0, |node| node.count)
    }

    pub(crate) fn root(&self) -> [u8; 32] {
        self.root.as_ref().map_or([0u8; 32], |node| node.hash)
    }

    /// Audit path for `index`, leaf-first, or `None` if the index is outside the
    /// tree.
    pub(crate) fn prove(&self, index: usize) -> Option<Vec<[u8; 32]>> {
        let node = self.root.as_ref()?;
        if index >= node.count {
            return None;
        }
        let mut path = Vec::new();
        collect(node, index, &mut path);
        Some(path)
    }
}

fn build(mut nodes: Vec<Node>) -> Node {
    debug_assert!(!nodes.is_empty());
    if nodes.len() == 1 {
        return nodes.pop().expect("one node");
    }
    let split = split_point(nodes.len());
    let right_nodes = nodes.split_off(split);
    let left = build(nodes);
    let right = build(right_nodes);
    Node {
        hash: node_hash(&left.hash, &right.hash),
        count: left.count + right.count,
        left: Some(Box::new(left)),
        right: Some(Box::new(right)),
    }
}

fn collect(node: &Node, index: usize, path: &mut Vec<[u8; 32]>) {
    let (Some(left), Some(right)) = (node.left.as_deref(), node.right.as_deref()) else {
        return;
    };
    if index < left.count {
        collect(left, index, path);
        path.push(right.hash);
    } else {
        collect(right, index - left.count, path);
        path.push(left.hash);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The verifier's `_recompute`, written independently of `Tree`: consumes the
    /// path from the back and fails on a path of the wrong length.
    fn recompute(leaf: [u8; 32], index: usize, size: usize, path: &[[u8; 32]]) -> Option<[u8; 32]> {
        if size == 1 {
            return Some(leaf);
        }
        let (sibling, inner) = path.split_last()?;
        let k = split_point(size);
        if index < k {
            Some(node_hash(&recompute(leaf, index, k, inner)?, sibling))
        } else {
            Some(node_hash(
                sibling,
                &recompute(leaf, index - k, size - k, inner)?,
            ))
        }
    }

    #[test]
    fn empty_and_single_leaf_trees_follow_the_rule() {
        let empty = Tree::from_lines(&[]);
        assert_eq!(empty.size(), 0);
        assert_eq!(empty.root(), [0u8; 32]);
        assert!(empty.prove(0).is_none());

        let line = b"{\"seq\":1}".to_vec();
        let one = Tree::from_lines(std::slice::from_ref(&line));
        assert_eq!(one.size(), 1);
        assert_eq!(one.root(), leaf_hash(&line));
        assert_eq!(one.prove(0), Some(vec![]));
        assert!(one.prove(1).is_none());
    }

    #[test]
    fn every_leaf_proves_to_the_root_for_logs_of_one_to_nine() {
        for size in 1..=9usize {
            let lines: Vec<Vec<u8>> = (0..size)
                .map(|i| format!("line-{i}").into_bytes())
                .collect();
            let tree = Tree::from_lines(&lines);
            let root = tree.root();
            for (index, line) in lines.iter().enumerate() {
                let path = tree.prove(index).unwrap();
                let leaf = leaf_hash(line);
                assert_eq!(
                    recompute(leaf, index, size, &path),
                    Some(root),
                    "size {size}, index {index}"
                );
            }
        }
    }

    #[test]
    fn path_lengths_are_the_go_producers_lengths() {
        let expected = [0usize, 1, 2, 2, 3, 3, 3, 3];
        for (offset, want) in expected.iter().enumerate() {
            let size = offset + 1;
            let lines: Vec<Vec<u8>> = (0..size).map(|i| format!("l{i}").into_bytes()).collect();
            let tree = Tree::from_lines(&lines);
            assert_eq!(tree.prove(0).unwrap().len(), *want, "size {size}");
        }
    }

    #[test]
    fn the_tree_agrees_with_the_go_producer_on_its_own_entry_lines() {
        // v2-log.ndjson was emitted from a Go store. Its entries were hashed there,
        // so reproducing its head root from the entry lines is a cross-language
        // check of the leaf rule and the split, not just of this crate's tests.
        let bundle = include_bytes!("../../../tools/bundle-verify/testdata/v2-log.ndjson");
        let first_newline = bundle
            .iter()
            .position(|byte| *byte == b'\n')
            .expect("fixture has a header line");
        let header: serde_json::Value =
            serde_json::from_slice(&bundle[..first_newline]).expect("fixture header is JSON");
        let entries = &bundle[first_newline + 1..];

        let log = crate::Log::parse(entries).expect("fixture entry lines parse");
        assert_eq!(log.len(), 12);
        assert_eq!(log.root_hex(), header["log_head"]["root"].as_str().unwrap());

        let path: Vec<String> = log
            .tree()
            .prove(0)
            .unwrap()
            .iter()
            .map(|hash| crate::to_hex(hash))
            .collect();
        let fixture: Vec<String> = header["proofs"][0]["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect();
        assert_eq!(path, fixture);
    }
}
