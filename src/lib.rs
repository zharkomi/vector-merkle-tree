extern crate ring;

use std::collections::HashMap;
use std::convert::AsRef;
use std::hash::Hash;
use std::mem;

use ring::digest::{Algorithm, Context, Digest};

pub struct MerkleTree {
    array: Vec<u8>,
    height: usize,
    items_count: usize,
    map: Option<HashMap<Vec<u8>, usize>>,
    algo: &'static Algorithm,
}

impl MerkleTree {
    pub fn new<T: AsRef<[u8]>>(values: &Vec<T>, algo: &'static Algorithm) -> MerkleTree {
        Self::new_with_flag(values, algo, false)
    }

    pub fn new_with_map<T: AsRef<[u8]>>(values: &Vec<T>, algo: &'static Algorithm) -> MerkleTree {
        Self::new_with_flag(values, algo, true)
    }

    pub fn new_with_flag<T: AsRef<[u8]>>(values: &Vec<T>, algo: &'static Algorithm, use_map: bool) -> MerkleTree {
        let (height, array, map) = build_tree(values, algo, use_map);
        MerkleTree {
            array: array,
            height: height,
            items_count: values.len(),
            map: map,
            algo: algo,
        }
    }

    pub fn build_proof<T: Eq + Hash + AsRef<[u8]>>(&self, value: &T) -> Option<Vec<u8>> {
        let hash = get_hash(value.as_ref(), self.algo).as_ref().to_vec();
        let index = self.find_item(&hash);
        let mut vec = vec![];
        match index {
            Some(i) => {
                vec.extend_from_slice(&self.array[(i * self.algo.output_len)..(i * self.algo.output_len + self.algo.output_len)]);
                Some(self.add_level(0, i, self.items_count, vec))
            }
            None => None
        }
    }

    fn find_item(&self, hash: &Vec<u8>) -> Option<usize> {
        match self.map {
            Some(ref m) => { // if we have a map of items
                match m.get(hash) {
                    None => None,
                    Some(index) => {
                        Some(*index)
                    }
                }
            }
            None => { // linear search item in a loop
                let mut result = None;
                for index in 0..self.items_count {
                    let start = index * self.algo.output_len;
                    if hash.as_slice() == &self.array[start..(start + self.algo.output_len)] {
                        result = Some(index);
                        break;
                    }
                }
                result
            }
        }
    }

    fn add_level(&self, start_index: usize, index: usize, mut level_len: usize, mut result: Vec<u8>) -> Vec<u8> {
        level_len += level_len & 1;
        let (sibling, parent) = calculate_relatives(index);
        result.extend_from_slice(&self.array[
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
        if self.is_empty() {
            return &[];
        }
        let root_index = self.array.len() - self.algo.output_len;
        &self.array[root_index..] // Last item
    }

    pub fn nodes_count(&self) -> usize {
        self.array.len() / self.algo.output_len
    }

    pub fn leafs_count(&self) -> usize {
        self.items_count
    }

    pub fn data_size(&self) -> usize {
        self.array.len()
    }

    pub fn height(&self) -> usize {
        self.height
    }

    pub fn validate(&self, proof: &Vec<u8>) -> bool {
        let mut hash = get_pair_hash(self.get_slice(proof, 0), self.get_slice(proof, 1), self.algo);
        for i in 2..(proof.len() / self.algo.output_len) {
            hash = get_pair_hash(hash.as_ref(), self.get_slice(proof, i), self.algo);
        }
        hash.as_ref() == self.get_root()
    }

    fn get_slice<'a>(&self, vec: &'a Vec<u8>, i: usize) -> &'a [u8] {
        &vec[(i * self.algo.output_len)..(i * self.algo.output_len + self.algo.output_len)]
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

fn build_tree<T: AsRef<[u8]>>(values: &Vec<T>, algo: &'static Algorithm, use_map: bool) -> (usize, Vec<u8>, Option<HashMap<Vec<u8>, usize>>) {
    let mut map: Option<HashMap<Vec<u8>, usize>> = if use_map { Some(HashMap::new()) } else { None };
    let vec_len = calculate_vec_len(values.len(), algo);
    let mut tree: Vec<u8> = Vec::with_capacity(vec_len);
    for (i, v) in values.iter().enumerate() { //Hash leafs
        let digest = get_hash(v.as_ref(), algo);
        let hash = digest.as_ref();
        tree.extend_from_slice(hash);
        match map {
            Some(ref mut m) => m.insert(hash.to_vec(), i),
            None => None,
        };
    }
    let height = build_level(&mut tree, 0, values.len(), algo);
    (height, tree, map)
}

fn calculate_vec_len(len: usize, algo: &'static Algorithm) -> usize {
    let mut result = len + (len & 1);
    let mut level = result;
    while level > 1 {
        level += level & 1;
        level = level / 2;
        result += level;
    }
    result * algo.output_len
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
    if level_len > 0 {
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