use crate::error::Error;
use bls12_381_plus::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

pub(crate) fn try_into_scalar(value: Vec<u8>) -> Result<Scalar, Error> {
    let mut bytes = [0u8; Scalar::BYTES];
    bytes.copy_from_slice(&value);
    let converted = {
        let maybe_coverted = Scalar::from_be_bytes(&bytes);

        if maybe_coverted.is_some().into() {
            maybe_coverted.unwrap()
        } else {
            return Err(Error::ScalarConversionError);
        }
    };
    Ok(converted)
}

/// Try Decompress G1
pub(crate) fn try_decompress_g1(value: Vec<u8>) -> Result<G1Affine, Error> {
    let mut bytes = [0u8; G1Affine::COMPRESSED_BYTES];
    bytes.copy_from_slice(&value);
    let maybe_g1 = G1Affine::from_compressed(&bytes);

    if maybe_g1.is_none().into() {
        return Err(Error::InvalidG1Point);
    } else {
        Ok(maybe_g1.unwrap())
    }
}

/// Try Decompress G2
pub(crate) fn try_decompress_g2(value: Vec<u8>) -> Result<G2Affine, Error> {
    let mut bytes = [0u8; G2Affine::COMPRESSED_BYTES];
    bytes.copy_from_slice(&value);
    let maybe_g2 = G2Affine::from_compressed(&bytes);

    if maybe_g2.is_none().into() {
        return Err(Error::InvalidG2Point);
    } else {
        Ok(maybe_g2.unwrap())
    }
}

/// Converts a Vector of maybe G1 into G1 or Err
pub fn try_into_g1(value: Vec<Vec<u8>>) -> Result<Vec<G1Projective>, Error> {
    Ok(value
        .iter()
        .map(|item| {
            let mut bytes = [0u8; G1Affine::COMPRESSED_BYTES];
            bytes.copy_from_slice(item);
            let g1_maybe = G1Affine::from_compressed(&bytes);

            if g1_maybe.is_none().into() {
                // Error::InvalidG1
                return Err(Error::InvalidG1Point);
            }
            Ok(g1_maybe.expect("it'll be fine, it passed the check"))
        })
        .map(|item| Ok(G1Projective::from(item?)))
        .collect::<Result<Vec<G1Projective>, Error>>()?)
}

/// Converts a Vector of maybe G2 into G2 or Err
pub fn try_into_g2(value: Vec<Vec<u8>>) -> Result<Vec<G2Projective>, Error> {
    Ok(value
        .iter()
        .map(|item| {
            let mut bytes = [0u8; G2Affine::COMPRESSED_BYTES];
            bytes.copy_from_slice(item);
            let g2_maybe = G2Affine::from_compressed(&bytes);

            if g2_maybe.is_none().into() {
                // Error::InvalidG2
                return Err(Error::InvalidG2Point);
            }
            Ok(g2_maybe.expect("it'll be fine, it passed the check"))
        })
        .map(|item| Ok(G2Projective::from(item?)))
        .collect::<Result<Vec<G2Projective>, Error>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    // pub use bls12_381_plus::elliptic_curve::bigint;
    // use bls12_381_plus::elliptic_curve::ops::MulByGenerator;
    use bls12_381_plus::elliptic_curve::Field;
    use bls12_381_plus::group::{Curve, Group};
    use bls12_381_plus::{G1Projective, G2Projective, Scalar};
    use rand::rngs::ThreadRng;

    #[test]
    fn test_try_into_scalar() {
        let scalar = Scalar::random(ThreadRng::default());
        let bytes = scalar.to_be_bytes();
        let result = try_into_scalar(bytes.to_vec());
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    fn test_try_decompress_g1() {
        let g1 = G1Projective::random(&mut rand::thread_rng());
        let g1_affine = g1.to_affine();
        let bytes = g1_affine.to_compressed();
        let result_affine = try_decompress_g1(bytes.to_vec()).unwrap();

        eprintln!(
            "Proj: {:?}\n\n Affine:{:?},\n\n Comp: {:?}\n\n DeAffine: {:?}",
            g1,
            g1_affine.clone(),
            bytes,
            result_affine
        );

        assert_eq!(g1_affine, result_affine);
    }

    #[test]
    fn test_try_decompress_g2() {
        let g2 = G2Projective::random(&mut rand::thread_rng());
        let bytes = g2.to_affine().to_compressed();
        let result = try_decompress_g2(bytes.to_vec());
        assert_eq!(result.is_ok(), true);
        // should match
        assert_eq!(result.unwrap(), g2.to_affine());
    }
}
