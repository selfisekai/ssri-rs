use crate::algorithm::Algorithm;
use crate::builder::Builder;
use crate::integrity::Integrity;

pub struct Checker {
    sri: Integrity,
    builder: Builder
}

impl Checker {
    pub fn new(sri: Integrity) -> Checker {
        let mut builder = Builder::new();
        let hash = sri.hashes.get(0).unwrap();
        builder.algorithm(hash.algorithm.clone());
        Checker { sri, builder }
    }
    pub fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.builder.input(data);
    }
    pub fn result(self) -> Option<Algorithm> {
        let sri = self.builder.result();
        let hash = sri.hashes.get(0).unwrap();
        for h in self.sri.hashes.iter() {
            if h.algorithm != hash.algorithm {
                return None
            } else if h == hash {
                return Some(h.algorithm.clone())
            } else {
                continue
            }
        }
        None
    }
}
