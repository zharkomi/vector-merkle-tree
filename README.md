# Vector-based Merkle Tree 

This is tree implementation for Rust language. Key features:
* Whole tree is kept in a single vector
![](https://habrastorage.org/webt/7_/in/4_/7_in4_ijawhhqj4f9pldunhl2mu.png)
* Commutative node concatenation function
```
hash(Hash0,Hash1) = hash(Hash1,Hash0) = Hash01 
```

## Usage example

```rust
{
    let values = vec!["one", "two", "three", "four"];
    let tree = MerkleTree::new(&values, ALGO);
    let proof = tree.build_proof(&"one");
    let vec = proof.unwrap();
    tree.validate(&vec);
}
```

Creation and proof build functions are about 7 times faster than in object graph tree.
