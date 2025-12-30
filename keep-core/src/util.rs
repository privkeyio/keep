#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

use zeroize::Zeroize;

pub fn zeroize_and_remove<K, V>(map: &mut HashMap<K, V>, key: &K) -> bool
where
    K: Eq + Hash,
    V: Zeroize,
{
    if let Some(mut value) = map.remove(key) {
        value.zeroize();
        true
    } else {
        false
    }
}

pub fn zeroize_and_remove_btree<K, V>(map: &mut BTreeMap<K, V>, key: &K) -> bool
where
    K: Ord,
    V: Zeroize,
{
    if let Some(mut value) = map.remove(key) {
        value.zeroize();
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    #[derive(Debug, Clone, PartialEq)]
    struct Secret([u8; 32]);

    impl Zeroize for Secret {
        fn zeroize(&mut self) {
            self.0.zeroize();
        }
    }

    #[test]
    fn test_zeroize_and_remove_hashmap() {
        let mut map = HashMap::new();
        let key = "test_key";
        let secret = Secret([42u8; 32]);
        map.insert(key, secret);

        let removed = zeroize_and_remove(&mut map, &key);
        assert!(removed);
        assert!(!map.contains_key(&key));
    }

    #[test]
    fn test_zeroize_and_remove_hashmap_missing_key() {
        let mut map: HashMap<&str, Secret> = HashMap::new();
        let removed = zeroize_and_remove(&mut map, &"missing");
        assert!(!removed);
    }

    #[test]
    fn test_zeroize_and_remove_btreemap() {
        let mut map = BTreeMap::new();
        let key = "test_key";
        let secret = Secret([42u8; 32]);
        map.insert(key, secret);

        let removed = zeroize_and_remove_btree(&mut map, &key);
        assert!(removed);
        assert!(!map.contains_key(&key));
    }

    #[test]
    fn test_zeroize_and_remove_btreemap_missing_key() {
        let mut map: BTreeMap<&str, Secret> = BTreeMap::new();
        let removed = zeroize_and_remove_btree(&mut map, &"missing");
        assert!(!removed);
    }
}
