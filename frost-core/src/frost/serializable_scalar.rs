//! FROST serializable scalar

use std::{
    fmt::{self, Debug},
    hash::{Hash, Hasher},
};

use crate::{Ciphersuite, Error, Field, FieldError, Group, Scalar};

#[cfg(feature = "serde")]
use crate::ScalarSerialization;

/// A FROST serializable scalar.
///
/// The serializable scalar is a field element in the scalar field that the secret polynomial is defined
/// over, corresponding to some x-coordinate for a polynomial f(x) = y.  MUST NOT be zero in the
/// field, as f(0) = the shared secret.
#[derive(Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = "C: Ciphersuite"))]
#[cfg_attr(feature = "serde", serde(try_from = "ScalarSerialization<C>"))]
#[cfg_attr(feature = "serde", serde(into = "ScalarSerialization<C>"))]
pub struct SerializableScalar<C: Ciphersuite>(pub Scalar<C>);

impl<C> SerializableScalar<C>
where
    C: Ciphersuite,
{
    /// Create a new SerializableScalar from a scalar. For internal use only.
    pub fn new(scalar: Scalar<C>) -> Self {
        Self(scalar)
    }

    /// Zeroize this scalar.
    pub fn zeroize(&mut self) {
        self.0 = <<C::Group as Group>::Field>::zero();
    }

    /// Derive an SerializableScalar from an arbitrary byte string.
    ///
    /// This feature is not part of the specification and is just a convenient
    /// way of creating identifiers.
    ///
    /// Each possible byte string will map to an uniformly random SerializableScalar.
    /// Returns an error if the ciphersuite does not support SerializableScalar derivation,
    /// or if the mapped SerializableScalar is zero (which is unpredictable, but should happen
    /// with negligible probability).
    pub fn derive(s: &[u8]) -> Result<Self, Error<C>> {
        let scalar = C::HID(s).ok_or(Error::IdentifierDerivationNotSupported)?;
        Ok(Self::new(scalar))
    }

    /// Serialize the SerializableScalar using the ciphersuite encoding.
    pub fn serialize(&self) -> <<C::Group as Group>::Field as Field>::Serialization {
        <<C::Group as Group>::Field>::serialize(&self.0)
    }

    /// Deserialize an SerializableScalar from a serialized buffer.
    /// Returns an error if it attempts to deserialize zero.
    pub fn deserialize(
        buf: &<<C::Group as Group>::Field as Field>::Serialization,
    ) -> Result<Self, Error<C>> {
        let scalar = <<C::Group as Group>::Field>::deserialize(buf)?;
        Ok(Self::new(scalar))
    }
}

#[cfg(feature = "serde")]
impl<C> TryFrom<ScalarSerialization<C>> for SerializableScalar<C>
where
    C: Ciphersuite,
{
    type Error = Error<C>;

    fn try_from(value: ScalarSerialization<C>) -> Result<Self, Self::Error> {
        Self::deserialize(&value.0)
    }
}

#[cfg(feature = "serde")]
impl<C> From<SerializableScalar<C>> for ScalarSerialization<C>
where
    C: Ciphersuite,
{
    fn from(value: SerializableScalar<C>) -> Self {
        Self(value.serialize())
    }
}

impl<C> Eq for SerializableScalar<C> where C: Ciphersuite {}

impl<C> Debug for SerializableScalar<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("SerializableScalar")
            .field(&hex::encode(
                <<C::Group as Group>::Field>::serialize(&self.0).as_ref(),
            ))
            .finish()
    }
}

#[allow(clippy::derived_hash_with_manual_eq)]
impl<C> Hash for SerializableScalar<C>
where
    C: Ciphersuite,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        <<C::Group as Group>::Field>::serialize(&self.0)
            .as_ref()
            .hash(state)
    }
}

impl<C> Ord for SerializableScalar<C>
where
    C: Ciphersuite,
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let serialized_self = <<C::Group as Group>::Field>::little_endian_serialize(&self.0);
        let serialized_other = <<C::Group as Group>::Field>::little_endian_serialize(&other.0);
        // The default cmp uses lexicographic order; so we need the elements in big endian
        serialized_self
            .as_ref()
            .iter()
            .rev()
            .cmp(serialized_other.as_ref().iter().rev())
    }
}

impl<C> PartialOrd for SerializableScalar<C>
where
    C: Ciphersuite,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let serialized_self = <<C::Group as Group>::Field>::little_endian_serialize(&self.0);
        let serialized_other = <<C::Group as Group>::Field>::little_endian_serialize(&other.0);
        // The default cmp uses lexicographic order; so we need the elements in big endian
        serialized_self
            .as_ref()
            .iter()
            .rev()
            .partial_cmp(serialized_other.as_ref().iter().rev())
    }
}

impl<C> std::ops::Mul<Scalar<C>> for SerializableScalar<C>
where
    C: Ciphersuite,
{
    type Output = Scalar<C>;

    fn mul(self, scalar: Scalar<C>) -> Scalar<C> {
        self.0 * scalar
    }
}

impl<C> std::ops::MulAssign<SerializableScalar<C>> for Scalar<C>
where
    C: Ciphersuite,
{
    fn mul_assign(&mut self, serializable_scalar: SerializableScalar<C>) {
        *self = *self * serializable_scalar.0
    }
}

impl<C> std::ops::Sub for SerializableScalar<C>
where
    C: Ciphersuite,
{
    type Output = Self;

    fn sub(self, rhs: SerializableScalar<C>) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<C> TryFrom<u16> for SerializableScalar<C>
where
    C: Ciphersuite,
{
    type Error = Error<C>;

    fn try_from(n: u16) -> Result<SerializableScalar<C>, Self::Error> {
        if n == 0 {
            Err(FieldError::InvalidZeroScalar.into())
        } else {
            // Classic left-to-right double-and-add algorithm that skips the first bit 1 (since
            // identifiers are never zero, there is always a bit 1), thus `sum` starts with 1 too.
            let one = <<C::Group as Group>::Field>::one();
            let mut sum = <<C::Group as Group>::Field>::one();

            let bits = (n.to_be_bytes().len() as u32) * 8;
            for i in (0..(bits - n.leading_zeros() - 1)).rev() {
                sum = sum + sum;
                if n & (1 << i) != 0 {
                    sum = sum + one;
                }
            }
            Ok(Self(sum))
        }
    }
}
