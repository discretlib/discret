//recuperer les differents policy_groups
//synchroniser le security group
//si nouveau groupe
//nosynch alert
//pour chaque policy dans les groupes
//recupérer les droits sur les schemas
//synchroniser les shemas un a un qui ont un droit read
//updater le daily log

//use std::collections::HashSet;

use std::collections::HashSet;

fn main() {
    let s1: HashSet<i32> = [0, 1, 2, 3, 4].iter().cloned().collect();
    let s2: HashSet<i32> = [3, 4].iter().cloned().collect();
    let expected: HashSet<i32> = [0, 1, 2].iter().cloned().collect();
    assert_eq!(&s1 - &s2, expected);
}

//If you want to perform this operation on vectors, you could convert to HashSet or BTreeSet and then create a vector from this:

fn vect_difference(v1: &Vec<i32>, v2: &Vec<i32>) -> Vec<i32> {
    let s1: HashSet<i32> = v1.iter().cloned().collect();
    let s2: HashSet<i32> = v2.iter().cloned().collect();
    (&s1 - &s2).iter().cloned().collect()
}

//
