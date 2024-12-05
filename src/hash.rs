use std::cmp::Ordering;
use std::fmt;

use base64::engine::general_purpose::STANDARD as STANDARD_BASE64;
use base64::Engine;

use crate::algorithm::Algorithm;
use crate::errors::Error;

/**
Represents a single algorithm/digest pair.

This is mostly internal, although users might interact with it directly on
occasion.
*/
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Hash {
    Sha512([u8; 64]),
    Sha384([u8; 48]),
    Sha256([u8; 32]),
    Sha1([u8; 20]),
    /// xxh3 is a non-cryptographic hash function that is very fast and can be
    /// used to speed up integrity calculations, at the cost of
    /// cryptographically-secure guarantees.
    ///
    /// `ssri` uses 128-bit xxh3 hashes, which have been shown to have no
    /// conflicts even on billions of hashes.
    Xxh3([u8; 16]),
}

impl Hash {
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Hash::Sha512(_) => Algorithm::Sha512,
            Hash::Sha384(_) => Algorithm::Sha384,
            Hash::Sha256(_) => Algorithm::Sha256,
            Hash::Sha1(_) => Algorithm::Sha1,
            Hash::Xxh3(_) => Algorithm::Xxh3,
        }
    }

    pub fn digest(&self) -> &[u8] {
        match self {
            Hash::Sha512(d) => d,
            Hash::Sha384(d) => d,
            Hash::Sha256(d) => d,
            Hash::Sha1(d) => d,
            Hash::Xxh3(d) => d,
        }
    }

    pub fn from_algorithm_digest(algorithm: Algorithm, digest: &[u8]) -> Result<Hash, Error> {
        match algorithm {
            Algorithm::Sha512 => {
                let mut hash = [0; 64];
                if digest.len() != hash.len() {
                    return Err(Error::ParseIntegrityError(format!(
                        "Digest has invalid length of {} bytes - a {} hash needs to have {} bytes",
                        digest.len(),
                        algorithm,
                        hash.len()
                    )));
                }
                hash.copy_from_slice(digest);
                Ok(Hash::Sha512(hash))
            }
            Algorithm::Sha384 => {
                let mut hash = [0; 48];
                if digest.len() != hash.len() {
                    return Err(Error::ParseIntegrityError(format!(
                        "Digest has invalid length of {} bytes - a {} hash needs to have {} bytes",
                        digest.len(),
                        algorithm,
                        hash.len()
                    )));
                }
                hash.copy_from_slice(digest);
                Ok(Hash::Sha384(hash))
            }
            Algorithm::Sha256 => {
                let mut hash = [0; 32];
                if digest.len() != hash.len() {
                    return Err(Error::ParseIntegrityError(format!(
                        "Digest has invalid length of {} bytes - a {} hash needs to have {} bytes",
                        digest.len(),
                        algorithm,
                        hash.len()
                    )));
                }
                hash.copy_from_slice(digest);
                Ok(Hash::Sha256(hash))
            }
            Algorithm::Sha1 => {
                let mut hash = [0; 20];
                if digest.len() != hash.len() {
                    return Err(Error::ParseIntegrityError(format!(
                        "Digest has invalid length of {} bytes - a {} hash needs to have {} bytes",
                        digest.len(),
                        algorithm,
                        hash.len()
                    )));
                }
                hash.copy_from_slice(digest);
                Ok(Hash::Sha1(hash))
            }
            Algorithm::Xxh3 => {
                let mut hash = [0; 16];
                if digest.len() != hash.len() {
                    return Err(Error::ParseIntegrityError(format!(
                        "Digest has invalid length of {} bytes - a {} hash needs to have {} bytes",
                        digest.len(),
                        algorithm,
                        hash.len()
                    )));
                }
                hash.copy_from_slice(digest);
                Ok(Hash::Xxh3(hash))
            }
        }
    }
}

impl PartialOrd for Hash {
    fn partial_cmp(&self, other: &Hash) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hash {
    fn cmp(&self, other: &Hash) -> Ordering {
        self.algorithm().cmp(&other.algorithm())
    }
}
impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}-{}",
            self.algorithm(),
            STANDARD_BASE64.encode(self.digest())
        )
    }
}

impl std::str::FromStr for Hash {
    type Err = Error;

    /// Tries to parse a [&str] into a [struct@Hash].
    /// Note the length of the digest is not validated to encode the number of
    /// bytes expected by the chosen hash algorithm.
    fn from_str(s: &str) -> Result<Hash, Self::Err> {
        let mut parsed = s.trim().split(|c| c == '-');
        let algorithm = parsed
            .next()
            .ok_or_else(|| Error::ParseIntegrityError(s.into()))?
            .parse()?;
        let digest_str = parsed
            .next()
            .ok_or_else(|| Error::ParseIntegrityError(s.into()))?
            .trim_end();
        let digest = STANDARD_BASE64
            .decode(digest_str)
            .map_err(|e| Error::ParseIntegrityError(e.to_string()))?;
        Ok(match algorithm {
            Algorithm::Sha512 => {
                let mut hash = [0; 64];
                if digest.len() != hash.len() {
                    return Err(Error::ParseIntegrityError(format!(
                        "Parsed {} bytes of hash - a {} hash should be {} bytes long",
                        digest.len(),
                        algorithm,
                        hash.len()
                    )));
                }
                hash.copy_from_slice(&digest);
                Hash::Sha512(hash)
            }
            Algorithm::Sha384 => {
                let mut hash = [0; 48];
                if digest.len() != hash.len() {
                    return Err(Error::ParseIntegrityError(format!(
                        "Parsed {} bytes of hash - a {} hash should be {} bytes long",
                        digest.len(),
                        algorithm,
                        hash.len()
                    )));
                }
                hash.copy_from_slice(&digest);
                Hash::Sha384(hash)
            }
            Algorithm::Sha256 => {
                let mut hash = [0; 32];
                if digest.len() != hash.len() {
                    return Err(Error::ParseIntegrityError(format!(
                        "Parsed {} bytes of hash - a {} hash should be {} bytes long",
                        digest.len(),
                        algorithm,
                        hash.len()
                    )));
                }
                hash.copy_from_slice(&digest);
                Hash::Sha256(hash)
            }
            Algorithm::Sha1 => {
                let mut hash = [0; 20];
                if digest.len() != hash.len() {
                    return Err(Error::ParseIntegrityError(format!(
                        "Parsed {} bytes of hash - a {} hash should be {} bytes long",
                        digest.len(),
                        algorithm,
                        hash.len()
                    )));
                }
                hash.copy_from_slice(&digest);
                Hash::Sha1(hash)
            }
            Algorithm::Xxh3 => {
                let mut hash = [0; 16];
                if digest.len() != hash.len() {
                    return Err(Error::ParseIntegrityError(format!(
                        "Parsed {} bytes of hash - a {} hash should be {} bytes long",
                        digest.len(),
                        algorithm,
                        hash.len()
                    )));
                }
                hash.copy_from_slice(&digest);
                Hash::Xxh3(hash)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Hash;

    #[test]
    fn hash_stringify() {
        assert_eq!(
            format!(
                "{}",
                // list(hashlib.sha256(b'ssri').digest())
                Hash::Sha256([
                    147, 173, 211, 33, 34, 65, 228, 109, 188, 158, 107, 211, 188, 16, 188, 192,
                    153, 126, 82, 213, 54, 128, 221, 0, 81, 60, 238, 24, 64, 203, 122, 38
                ])
            ),
            // "sha256-" + base64.encodebytes(hashlib.sha256(b'ssri').digest()).decode('utf-8').strip()
            "sha256-k63TISJB5G28nmvTvBC8wJl+UtU2gN0AUTzuGEDLeiY="
        )
    }

    #[test]
    fn parsing() {
        assert_eq!(
            " sha256-k63TISJB5G28nmvTvBC8wJl+UtU2gN0AUTzuGEDLeiY= \n"
                .parse::<Hash>()
                .unwrap(),
            Hash::Sha256([
                147, 173, 211, 33, 34, 65, 228, 109, 188, 158, 107, 211, 188, 16, 188, 192, 153,
                126, 82, 213, 54, 128, 221, 0, 81, 60, 238, 24, 64, 203, 122, 38
            ])
        )
    }

    #[test]
    #[should_panic]
    fn bad_algorithm() {
        // TODO - test the actual error returned when it's more valuable
        "sha7-deadbeef==".parse::<Hash>().unwrap();
    }

    #[test]
    #[should_panic]
    fn bad_length() {
        // TODO - test the actual error returned when it's more valuable
        "sha1-deadbeef==".parse::<Hash>().unwrap();
    }

    #[test]
    fn ordering() {
        let mut arr = [
            Hash::Sha1([0; 20]),
            Hash::Sha256([0; 32]),
            Hash::Sha384([0; 48]),
            Hash::Sha512([0; 64]),
            Hash::Xxh3([0; 16]),
        ];
        arr.sort_unstable();
        assert_eq!(
            arr,
            [
                Hash::Sha512([0; 64]),
                Hash::Sha384([0; 48]),
                Hash::Sha256([0; 32]),
                Hash::Sha1([0; 20]),
                Hash::Xxh3([0; 16]),
            ]
        )
    }
}
