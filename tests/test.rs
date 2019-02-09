extern crate ring;
extern crate vmt;

use ring::digest::{Algorithm, Context, Digest, SHA512};

use vmt::MerkleTree;

static ALGO: &'static Algorithm = &SHA512;

macro_rules! test_tree {
    ($constructor:ident,
    $test_tree_0:ident,
    $test_tree_1:ident,
    $test_tree_2:ident,
    $test_tree_2_reverse:ident,
    $test_tree_3:ident,
    $test_tree_4:ident,
    $test_tree_4_reverse:ident,
    $test_equal:ident,
    $test_proof:ident,
    $test_bad_proof:ident) => {
        #[test]
        fn $test_tree_0() {
            let values: Vec<&str> = vec![];
            let _tree = MerkleTree::$constructor(&values, ALGO);

            assert_eq!(true, _tree.is_empty());
            assert_eq!(0, _tree.height());
            assert_eq!(0, _tree.nodes_count());
            assert_eq!(0, _tree.data_size());
            let empty_root: Vec<u8> = vec![];
            assert_eq!(empty_root, _tree.get_root());
        }

        #[test]
        fn $test_tree_1() {
            let values = vec!["one"];
            let _tree = MerkleTree::new(&values, ALGO);

            let _d0: Digest = vmt::get_hash(values[0].as_ref(), ALGO);
            let _pair = vmt::get_pair_hash(_d0.as_ref(), _d0.as_ref(), ALGO);

            assert_eq!(false, _tree.is_empty());
            assert_eq!(2, _tree.height());
            assert_eq!(3, _tree.nodes_count());
            assert_eq!(3 * ALGO.output_len, _tree.data_size());
            assert_eq!(_pair.as_ref(), _tree.get_root());
        }

        #[test]
        fn $test_tree_2() {
            let values = vec!["one", "two"];
            let _tree = MerkleTree::new(&values, ALGO);

            let _d0: Digest = vmt::get_hash(values[0].as_ref(), ALGO);
            let _d1: Digest = vmt::get_hash(values[1].as_ref(), ALGO);

            let _pair = vmt::get_pair_hash(_d0.as_ref(), _d1.as_ref(), ALGO);

            assert_eq!(false, _tree.is_empty());
            assert_eq!(2, _tree.height());
            assert_eq!(3, _tree.nodes_count());
            assert_eq!(3 * ALGO.output_len, _tree.data_size());
            assert_eq!(_pair.as_ref(), _tree.get_root());
        }

        #[test]
        fn $test_tree_2_reverse() {
            let values1 = vec!["one", "two"];
            let _tree1 = MerkleTree::new(&values1, ALGO);

            let values2 = vec!["two", "one"];
            let _tree2 = MerkleTree::new(&values2, ALGO);

            assert_eq!(_tree1.get_root(), _tree2.get_root());
        }

        #[test]
        fn $test_tree_3() {
            let values = vec!["one", "two", "four"];
            let _tree = MerkleTree::new(&values, ALGO);

            let _d0: Digest = vmt::get_hash(values[0].as_ref(), ALGO);
            let _d1: Digest = vmt::get_hash(values[1].as_ref(), ALGO);
            let _d2: Digest = vmt::get_hash(values[2].as_ref(), ALGO);
            let _d3: Digest = vmt::get_hash(values[2].as_ref(), ALGO);

            let _d01 = hash_pair(_d0.as_ref(), _d1.as_ref(), ALGO);
            let _d32 = hash_pair(_d2.as_ref(), _d3.as_ref(), ALGO);
            let _pair = vmt::get_pair_hash(_d32.as_ref(), _d01.as_ref(), ALGO);

            assert_eq!(false, _tree.is_empty());
            assert_eq!(3, _tree.height());
            assert_eq!(7, _tree.nodes_count());
            assert_eq!(7 * ALGO.output_len, _tree.data_size());
            assert_eq!(_pair.as_ref(), _tree.get_root());
        }

        #[test]
        fn $test_tree_4() {
            let values = vec!["one", "two", "four", "three"];
            let _tree = MerkleTree::new(&values, ALGO);

            let _d0: Digest = vmt::get_hash(values[0].as_ref(), ALGO);
            let _d1: Digest = vmt::get_hash(values[1].as_ref(), ALGO);
            let _d2: Digest = vmt::get_hash(values[2].as_ref(), ALGO);
            let _d3: Digest = vmt::get_hash(values[3].as_ref(), ALGO);

            let _d01 = hash_pair(_d0.as_ref(), _d1.as_ref(), ALGO);
            let _d32 = hash_pair(_d2.as_ref(), _d3.as_ref(), ALGO);
            let _pair = vmt::get_pair_hash(_d32.as_ref(), _d01.as_ref(), ALGO);

            assert_eq!(false, _tree.is_empty());
            assert_eq!(3, _tree.height());
            assert_eq!(7, _tree.nodes_count());
            assert_eq!(7 * ALGO.output_len, _tree.data_size());
            assert_eq!(_pair.as_ref(), _tree.get_root());
        }

        #[test]
        fn $test_tree_4_reverse() {
            let values1 = vec!["one", "two", "three", "four"];
            let _tree1 = MerkleTree::new(&values1, ALGO);

            let values2 = vec!["four", "three", "two", "one"];
            let _tree2 = MerkleTree::new(&values2, ALGO);

            assert_eq!(_tree1.get_root(), _tree2.get_root());
        }

        #[test]
        fn $test_equal() {
            let values = vec!["one", "one", "one", "one"];
            let _tree = MerkleTree::new(&values, ALGO);

            let _d0: Digest = vmt::get_hash(values[0].as_ref(), ALGO);
            let _d1: Digest = vmt::get_hash(values[1].as_ref(), ALGO);
            let _d2: Digest = vmt::get_hash(values[2].as_ref(), ALGO);
            let _d3: Digest = vmt::get_hash(values[3].as_ref(), ALGO);

            let _d01 = hash_pair(_d0.as_ref(), _d1.as_ref(), ALGO);
            let _d32 = hash_pair(_d2.as_ref(), _d3.as_ref(), ALGO);
            let _pair = vmt::get_pair_hash(_d32.as_ref(), _d01.as_ref(), ALGO);

            assert_eq!(false, _tree.is_empty());
            assert_eq!(3, _tree.height());
            assert_eq!(7, _tree.nodes_count());
            assert_eq!(7 * ALGO.output_len, _tree.data_size());
            assert_eq!(_pair.as_ref(), _tree.get_root());
        }

        #[test]
        fn $test_proof() {
            let values = vec!["one", "two", "three", "four"];
            let _tree = MerkleTree::new(&values, ALGO);

            for v in values {
                let proof = _tree.build_proof(&v);
                assert_eq!(true, proof.is_some());
                let vec = proof.unwrap();
                assert_eq!(2, vec.len());
                _tree.validate(v, vec, _tree.get_root());
            }

            let absent = vec!["qqq", "www", "eee", "rrr"];
            for v in absent {
                let proof = _tree.build_proof(&v);
                assert_eq!(true, proof.is_none());
            }
        }

        #[test]
        fn $test_bad_proof() {
            let values = vec!["one", "two", "three", "four"];
            let _tree = MerkleTree::new(&values, ALGO);
            let proof = _tree.build_proof(&"one");

            assert_eq!(true, proof.is_some());
            let _d0: Digest = vmt::get_hash("five".as_ref(), ALGO);
            let proof_vec = proof.unwrap();
            let vec = vec![proof_vec[0], proof_vec[1], _d0.as_ref()];
            assert_eq!(false, _tree.validate(&"one", vec, _tree.get_root()));
        }
    }
}

test_tree!(new, new_test_tree_0, new_test_tree_1, new_test_tree_2, new_test_tree_2_reverse, new_test_tree_3,
new_test_tree_4, new_test_tree_4_reverse, new_test_equal, new_test_proof, new_test_bad_proof);

test_tree!(new_with_map, new_with_map_test_tree_0, new_with_map_test_tree_1, new_with_map_test_tree_2, new_with_map_test_tree_2_reverse, new_with_map_test_tree_3,
new_with_map_test_tree_4, new_with_map_test_tree_4_reverse, new_with_map_test_equal, new_with_map_test_proof, new_with_map_test_bad_proof);

fn hash_pair(x: &[u8], y: &[u8], algo: &'static Algorithm) -> Digest {
    let mut ctx = Context::new(algo);
    ctx.update(x);
    ctx.update(y);
    ctx.finish()
}
