extern crate ring;
extern crate vmt;

macro_rules! test_tree {
    ($constructor:ident) => {
        use ring::digest::{Algorithm, Context, Digest, SHA512};

        use vmt::MerkleTree;

        static ALGO: &'static Algorithm = &SHA512;

        #[test]
        fn test_tree_0() {
            let values: Vec<&str> = vec![];
            let tree = MerkleTree::$constructor(&values, ALGO);

            assert_eq!(true, tree.is_empty());
            assert_eq!(0, tree.height());
            assert_eq!(0, tree.nodes_count());
            assert_eq!(0, tree.data_size());
            let empty_root: Vec<u8> = vec![];
            assert_eq!(empty_root, tree.get_root());
        }

        #[test]
        fn test_tree_1() {
            let values = vec!["one"];
            let tree = MerkleTree::$constructor(&values, ALGO);

            let d0: Digest = vmt::get_hash(values[0].as_ref(), ALGO);
            let _pair = vmt::get_pair_hash(d0.as_ref(), d0.as_ref(), ALGO);

            assert_eq!(false, tree.is_empty());
            assert_eq!(2, tree.height());
            assert_eq!(3, tree.nodes_count());
            assert_eq!(3 * ALGO.output_len, tree.data_size());
            assert_eq!(_pair.as_ref(), tree.get_root());
        }

        #[test]
        fn test_tree_2() {
            let values = vec!["one", "two"];
            let tree = MerkleTree::$constructor(&values, ALGO);

            let d0: Digest = vmt::get_hash(values[0].as_ref(), ALGO);
            let d1: Digest = vmt::get_hash(values[1].as_ref(), ALGO);

            let _pair = vmt::get_pair_hash(d0.as_ref(), d1.as_ref(), ALGO);

            assert_eq!(false, tree.is_empty());
            assert_eq!(2, tree.height());
            assert_eq!(3, tree.nodes_count());
            assert_eq!(3 * ALGO.output_len, tree.data_size());
            assert_eq!(_pair.as_ref(), tree.get_root());
        }

        #[test]
        fn test_tree_2_reverse() {
            let values1 = vec!["one", "two"];
            let tree1 = MerkleTree::$constructor(&values1, ALGO);

            let values2 = vec!["two", "one"];
            let tree2 = MerkleTree::$constructor(&values2, ALGO);

            assert_eq!(tree1.get_root(), tree2.get_root());
        }

        #[test]
        fn test_tree_3() {
            let values = vec!["one", "two", "four"];
            let tree = MerkleTree::$constructor(&values, ALGO);

            let d0: Digest = vmt::get_hash(values[0].as_ref(), ALGO);
            let d1: Digest = vmt::get_hash(values[1].as_ref(), ALGO);
            let d2: Digest = vmt::get_hash(values[2].as_ref(), ALGO);
            let d3: Digest = vmt::get_hash(values[2].as_ref(), ALGO);

            let d01 = hash_pair(d0.as_ref(), d1.as_ref(), ALGO);
            let d32 = hash_pair(d2.as_ref(), d3.as_ref(), ALGO);
            let _pair = vmt::get_pair_hash(d32.as_ref(), d01.as_ref(), ALGO);

            assert_eq!(false, tree.is_empty());
            assert_eq!(3, tree.height());
            assert_eq!(7, tree.nodes_count());
            assert_eq!(7 * ALGO.output_len, tree.data_size());
            assert_eq!(_pair.as_ref(), tree.get_root());
        }

        #[test]
        fn test_tree_4() {
            let values = vec!["one", "two", "four", "three"];
            let tree = MerkleTree::$constructor(&values, ALGO);

            let d0: Digest = vmt::get_hash(values[0].as_ref(), ALGO);
            let d1: Digest = vmt::get_hash(values[1].as_ref(), ALGO);
            let d2: Digest = vmt::get_hash(values[2].as_ref(), ALGO);
            let d3: Digest = vmt::get_hash(values[3].as_ref(), ALGO);

            let d01 = hash_pair(d0.as_ref(), d1.as_ref(), ALGO);
            let d32 = hash_pair(d2.as_ref(), d3.as_ref(), ALGO);
            let _pair = vmt::get_pair_hash(d32.as_ref(), d01.as_ref(), ALGO);

            assert_eq!(false, tree.is_empty());
            assert_eq!(3, tree.height());
            assert_eq!(7, tree.nodes_count());
            assert_eq!(7 * ALGO.output_len, tree.data_size());
            assert_eq!(_pair.as_ref(), tree.get_root());
        }

        #[test]
        fn test_tree_4_reverse() {
            let values1 = vec!["one", "two", "three", "four"];
            let tree1 = MerkleTree::$constructor(&values1, ALGO);

            let values2 = vec!["four", "three", "two", "one"];
            let tree2 = MerkleTree::$constructor(&values2, ALGO);

            assert_eq!(tree1.get_root(), tree2.get_root());
        }

        #[test]
        fn test_equal() {
            let values = vec!["one", "one", "one", "one"];
            let tree = MerkleTree::$constructor(&values, ALGO);

            let d0: Digest = vmt::get_hash(values[0].as_ref(), ALGO);
            let d1: Digest = vmt::get_hash(values[1].as_ref(), ALGO);
            let d2: Digest = vmt::get_hash(values[2].as_ref(), ALGO);
            let d3: Digest = vmt::get_hash(values[3].as_ref(), ALGO);

            let d01 = hash_pair(d0.as_ref(), d1.as_ref(), ALGO);
            let d32 = hash_pair(d2.as_ref(), d3.as_ref(), ALGO);
            let _pair = vmt::get_pair_hash(d32.as_ref(), d01.as_ref(), ALGO);

            assert_eq!(false, tree.is_empty());
            assert_eq!(3, tree.height());
            assert_eq!(7, tree.nodes_count());
            assert_eq!(7 * ALGO.output_len, tree.data_size());
            assert_eq!(_pair.as_ref(), tree.get_root());
        }

        #[test]
        fn test_proof() {
            let values = vec!["one", "two", "three", "four"];
            let tree = MerkleTree::$constructor(&values, ALGO);

            for v in values {
                let proof = tree.build_proof(&v);
                assert_eq!(true, proof.is_some());
                let vec = proof.unwrap();
                assert_eq!(3 * ALGO.output_len, vec.len());
                tree.validate(&vec);
            }

            let absent = vec!["qqq", "www", "eee", "rrr"];
            for v in absent {
                let proof = tree.build_proof(&v);
                assert_eq!(true, proof.is_none());
            }
        }

        #[test]
        fn test_bad_proof() {
            let values = vec!["one", "two", "three", "four"];
            let tree = MerkleTree::$constructor(&values, ALGO);
            let proof = tree.build_proof(&"one");

            assert_eq!(true, proof.is_some());
            let mut proof_vec = proof.unwrap();
            proof_vec[100] += 1;
            assert_eq!(false, tree.validate(&proof_vec));
        }

        fn hash_pair(x: &[u8], y: &[u8], algo: &'static Algorithm) -> Digest {
            let mut ctx = Context::new(algo);
            ctx.update(x);
            ctx.update(y);
            ctx.finish()
        }
    }
}

mod test {
    test_tree!(new);
}

mod test_with_map {
    test_tree!(new_with_map);
}
