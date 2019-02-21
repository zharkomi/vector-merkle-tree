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
        Self::new_internal(values, algo, false)
    }

    pub fn new_with_map<T: AsRef<[u8]>>(values: &Vec<T>, algo: &'static Algorithm) -> MerkleTree {
        Self::new_internal(values, algo, true)
    }

    fn new_internal<T: AsRef<[u8]>>(values: &Vec<T>, algo: &'static Algorithm, use_map: bool) -> MerkleTree {
        let (height, array, map) = build_tree(values, algo, use_map);
        MerkleTree {
            array: array,
            height: height,
            items_count: values.len(),
            map: map,
            algo: algo,
        }
    }

    pub fn build_proof<T: Eq + Hash + AsRef<[u8]>>(&self, value: &T) -> Option<Vec<&[u8]>> {
        let hash = get_hash(value.as_ref(), self.algo).as_ref().to_vec();
        match self.map {
            Some(ref m) => { // if we have a map of items
                match m.get(&hash) {
                    None => None,
                    Some(index) => {
                        Some(self.add_level(0, *index, self.items_count, vec![]))
                    }
                }
            }
            None => { // linear search item in a loop
                'items_loop: for index in 0..self.items_count {
                    for byte in 0..self.algo.output_len {
                        if self.array[index * self.algo.output_len + byte] != hash[byte] {
                            continue 'items_loop;
                        }
                    }
                    return Some(self.add_level(0, index, self.items_count, vec![]));
                }
                None
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

    pub fn validate<T: AsRef<[u8]>>(&self, value: T, proof: Vec<&[u8]>, root: &[u8]) -> bool {
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

fn build_tree<T: AsRef<[u8]>>(values: &Vec<T>, algo: &'static Algorithm, use_map: bool) -> (usize, Vec<u8>, Option<HashMap<Vec<u8>, usize>>) {
    let mut map: Option<HashMap<Vec<u8>, usize>> = if use_map { Some(HashMap::new()) } else { None };
    let mut tree: Vec<u8> = vec![];
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