extern crate ring;

use std::collections::HashMap;
use std::convert::AsRef;
use std::fmt::Display;
use std::hash::Hash;
use std::mem;

use ring::digest::{Algorithm, Context, Digest};

pub struct MerkleTree<T> {
    array: Vec<u8>,
    height: usize,
    map: HashMap<T, usize>,
    algo: &'static Algorithm,
}

impl<T: Eq + Hash + Clone + Display + AsRef<[u8]>> MerkleTree<T> {
    pub fn new(values: &Vec<T>, algo: &'static Algorithm) -> MerkleTree<T> {
        let (h, a) = build_tree(values, algo);
        MerkleTree {
            array: a,
            height: h,
            map: map_items(values),
            algo: algo,
        }
    }

    pub fn build_proof(&self, value: &T) -> Option<Vec<&[u8]>> {
        match self.map.get(value) {
            None => None,
            Some(v) => {
                Some(self.add_level(0, *v, self.map.len(), vec![]))
            }
        }
    }

    fn add_level<'a>(&'a self, start_index: usize, index: usize, mut level_len: usize, mut result: Vec<&'a [u8]>) -> Vec<&'a [u8]> {
        level_len += level_len & 1;
        let (sibling, parent) = calculate_relatives(index);
        result.push(&self.array[
            (start_index + sibling * self.algo.output_len)..(start_index + sibling * self.algo.output_len + self.algo.output_len)
            ]); //Add sibling to result
        let next_level_len = level_len / 2;
        if next_level_len == 1 { // Do not include root to proof
            return result;
        }
        self.add_level(start_index + level_len * self.algo.output_len, parent, next_level_len, result)
    }

    pub fn is_empty(&self) -> bool {
        self.nodes_count() == 0
    }

    pub fn get_root(&self) -> &[u8] {
        if (self.is_empty()) {
            return &[];
        }
        let root_index = self.array.len() - self.algo.output_len;
        &self.array[root_index..] // Last item
    }

    pub fn nodes_count(&self) -> usize {
        self.array.len() / self.algo.output_len
    }

    pub fn data_size(&self) -> usize {
        self.array.len()
    }

    pub fn height(&self) -> usize {
        self.height
    }

    pub fn validate(&self, value: T, proof: Vec<&[u8]>, root: &[u8]) -> bool {
        proof.iter()
            .fold(
                get_hash(value.as_ref(), self.algo),
                |a, b| get_pair_hash(a.as_ref(), b, self.algo),
            ).as_ref().to_vec() == root
    }
}

fn calculate_relatives(index: usize) -> (usize, usize) {
    let mut sibling = index;
    if index & 1 == 0 {
        sibling += 1
    } else {
        sibling -= 1
    };
    let parent = (index + 1 + ((index + 1) & 1)) / 2 - 1;
    (sibling, parent)
}

fn map_items<T: Eq + Hash + Clone>(values: &Vec<T>) -> HashMap<T, usize> {
    let mut result: HashMap<T, usize> = HashMap::new();
    for (i, x) in values.iter().enumerate() {
        result.insert(x.clone(), i);
    }
    result
}

fn build_tree<T: AsRef<[u8]>>(values: &Vec<T>, algo: &'static Algorithm) -> (usize, Vec<u8>) {
    let mut tree: Vec<u8> = vec![];
    for v in values { //Hash leafs
        tree.extend_from_slice(get_hash(v.as_ref(), algo).as_ref());
    }
    let height = build_level(&mut tree, 0, values.len(), algo);
    (height, tree)
}

fn build_level(tree: &mut Vec<u8>, prev_level_start: usize, mut prev_level_len: usize, algo: &'static Algorithm) -> usize {
    if prev_level_len & 1 == 1 { //Previous level has odd number of children
        let prev = &tree[(prev_level_start * algo.output_len + (prev_level_len - 1) * algo.output_len)..]
            .to_owned();
        tree.extend_from_slice(prev); //Duplicate last item
        prev_level_len += 1;
    }
    let level_len = prev_level_len / 2;
    for i in 0..level_len {
        let begin = prev_level_start * algo.output_len + i * 2 * algo.output_len;
        let middle = begin + algo.output_len;
        let end = middle + algo.output_len;
        let hash = get_pair_hash(
            &tree[begin..middle], //Left node
            &tree[middle..end], //Right node
            algo);
        tree.extend_from_slice(hash.as_ref());
    };
    if level_len > 1 {
        return build_level(tree, prev_level_start + prev_level_len, level_len, algo) + 1;
    }
    if (level_len > 0) {
        return 2;
    }
    return 0;
}

pub fn get_pair_hash(x: &[u8], y: &[u8], algo: &'static Algorithm) -> Digest {
    let mut left = x;
    let mut right = y;
    for i in 0..algo.output_len { //Sort left and right before concatenation
        if left[i] > right[i] {
            mem::swap(&mut left, &mut right);
            break;
        }
        if left[i] < right[i] {
            break;
        }
    }
    let mut ctx = Context::new(algo);
    ctx.update(left);
    ctx.update(right);
    ctx.finish()
}

pub fn get_hash(x: &[u8], algo: &'static Algorithm) -> Digest {
    let mut ctx = Context::new(algo);
    ctx.update(x);
    ctx.finish()
}