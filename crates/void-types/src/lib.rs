#![forbid(unsafe_code)]

use core::fmt;

pub const ENVELOPE_VERSION: u16 = 1;
pub const ENVELOPE_HEADER_LEN: usize = 43;
pub const MAX_ENVELOPE_SIZE: usize = 65_536;
const MAGIC: [u8; 4] = *b"VRMS";

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpaqueId<const N: usize>([u8; N]);

impl<const N: usize> OpaqueId<N> {
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> fmt::Debug for OpaqueId<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "OpaqueId<{N}>(REDACTED)")
    }
}

pub type RoomId = OpaqueId<16>;
pub type MessageId = OpaqueId<16>;
pub type RoutingHandle = OpaqueId<32>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EnvelopeKind {
    GroupControl = 1,
    Application = 2,
}

impl TryFrom<u8> for EnvelopeKind {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::GroupControl),
            2 => Ok(Self::Application),
            other => Err(DecodeError::UnknownKind(other)),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    kind: EnvelopeKind,
    routing_handle: RoutingHandle,
    payload: Vec<u8>,
}

impl fmt::Debug for Envelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Envelope")
            .field("version", &ENVELOPE_VERSION)
            .field("kind", &self.kind)
            .field("routing_handle", &"REDACTED")
            .field("payload_len", &self.payload.len())
            .field("payload", &"REDACTED")
            .finish()
    }
}

impl Envelope {
    pub fn new(
        kind: EnvelopeKind,
        routing_handle: RoutingHandle,
        payload: Vec<u8>,
    ) -> Result<Self, EncodeError> {
        let total = ENVELOPE_HEADER_LEN
            .checked_add(payload.len())
            .ok_or(EncodeError::TooLarge)?;
        if total > MAX_ENVELOPE_SIZE {
            return Err(EncodeError::TooLarge);
        }
        Ok(Self {
            kind,
            routing_handle,
            payload,
        })
    }

    pub const fn kind(&self) -> EnvelopeKind {
        self.kind
    }

    pub const fn routing_handle(&self) -> &RoutingHandle {
        &self.routing_handle
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let total = ENVELOPE_HEADER_LEN
            .checked_add(self.payload.len())
            .ok_or(EncodeError::TooLarge)?;
        if total > MAX_ENVELOPE_SIZE {
            return Err(EncodeError::TooLarge);
        }
        let payload_len = u32::try_from(self.payload.len()).map_err(|_| EncodeError::TooLarge)?;
        let mut frame = Vec::with_capacity(total);
        frame.extend_from_slice(&MAGIC);
        frame.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
        frame.push(self.kind as u8);
        frame.extend_from_slice(self.routing_handle.as_bytes());
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.extend_from_slice(&self.payload);
        Ok(frame)
    }

    pub fn decode(frame: &[u8]) -> Result<Self, DecodeError> {
        if frame.len() < ENVELOPE_HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if frame.len() > MAX_ENVELOPE_SIZE {
            return Err(DecodeError::TooLarge);
        }
        if frame[..4] != MAGIC {
            return Err(DecodeError::InvalidMagic);
        }
        let version = u16::from_be_bytes([frame[4], frame[5]]);
        if version != ENVELOPE_VERSION {
            return Err(DecodeError::UnsupportedVersion(version));
        }
        let kind = EnvelopeKind::try_from(frame[6])?;
        let mut route = [0; 32];
        route.copy_from_slice(&frame[7..39]);
        let payload_len = u32::from_be_bytes([frame[39], frame[40], frame[41], frame[42]]);
        let payload_len = usize::try_from(payload_len).map_err(|_| DecodeError::LengthMismatch)?;
        let expected_len = ENVELOPE_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(DecodeError::LengthMismatch)?;
        if expected_len != frame.len() {
            return Err(DecodeError::LengthMismatch);
        }
        Ok(Self {
            kind,
            routing_handle: RoutingHandle::from_bytes(route),
            payload: frame[ENVELOPE_HEADER_LEN..].to_vec(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    TooLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    TooShort,
    TooLarge,
    InvalidMagic,
    UnsupportedVersion(u16),
    UnknownKind(u8),
    LengthMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn handle() -> RoutingHandle {
        RoutingHandle::from_bytes([7; 32])
    }

    #[test]
    fn frame_round_trips_byte_for_byte() {
        let envelope =
            Envelope::new(EnvelopeKind::Application, handle(), b"opaque".to_vec()).unwrap();
        let encoded = envelope.encode().unwrap();
        assert_eq!(Envelope::decode(&encoded).unwrap(), envelope);
        assert_eq!(&encoded[..4], b"VRMS");
    }

    #[test]
    fn accepts_exact_maximum_and_rejects_oversize() {
        let max_payload_len = MAX_ENVELOPE_SIZE - ENVELOPE_HEADER_LEN;
        let payload = vec![0x5a; max_payload_len];
        let envelope = Envelope::new(EnvelopeKind::GroupControl, handle(), payload).unwrap();
        let encoded = envelope.encode().unwrap();
        assert_eq!(encoded.len(), MAX_ENVELOPE_SIZE);
        assert_eq!(Envelope::decode(&encoded).unwrap(), envelope);
        assert_eq!(
            Envelope::new(
                EnvelopeKind::GroupControl,
                handle(),
                vec![0; max_payload_len + 1]
            ),
            Err(EncodeError::TooLarge)
        );
        let mut oversized = encoded;
        oversized.push(0);
        assert_eq!(Envelope::decode(&oversized), Err(DecodeError::TooLarge));
    }

    #[test]
    fn rejects_every_truncation_and_trailing_data() {
        let frame = Envelope::new(EnvelopeKind::Application, handle(), vec![1, 2, 3])
            .unwrap()
            .encode()
            .unwrap();
        for end in 0..frame.len() {
            assert!(Envelope::decode(&frame[..end]).is_err());
        }
        let mut trailing = frame;
        trailing.push(0);
        assert_eq!(
            Envelope::decode(&trailing),
            Err(DecodeError::LengthMismatch)
        );
    }

    #[test]
    fn rejects_invalid_header_fields_and_lengths() {
        let frame = Envelope::new(EnvelopeKind::Application, handle(), vec![1])
            .unwrap()
            .encode()
            .unwrap();
        let mut invalid = frame.clone();
        invalid[0] = 0;
        assert_eq!(Envelope::decode(&invalid), Err(DecodeError::InvalidMagic));
        let mut invalid = frame.clone();
        invalid[5] = 2;
        assert_eq!(
            Envelope::decode(&invalid),
            Err(DecodeError::UnsupportedVersion(2))
        );
        let mut invalid = frame.clone();
        invalid[6] = 255;
        assert_eq!(
            Envelope::decode(&invalid),
            Err(DecodeError::UnknownKind(255))
        );
        let mut invalid = frame;
        invalid[42] = 2;
        assert_eq!(Envelope::decode(&invalid), Err(DecodeError::LengthMismatch));
    }

    #[test]
    fn debug_output_redacts_identifiers_and_payloads() {
        let envelope =
            Envelope::new(EnvelopeKind::Application, handle(), b"secret".to_vec()).unwrap();
        let debug = format!("{envelope:?} {:?}", handle());
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("7, 7"));
        assert!(debug.contains("REDACTED"));
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(frame in prop::collection::vec(any::<u8>(), 0..=MAX_ENVELOPE_SIZE + 1)) {
            let _ = Envelope::decode(&frame);
        }

        #[test]
        fn generated_envelopes_round_trip(payload in prop::collection::vec(any::<u8>(), 0..=MAX_ENVELOPE_SIZE - ENVELOPE_HEADER_LEN), kind in 1u8..=2) {
            let kind = EnvelopeKind::try_from(kind).unwrap();
            let envelope = Envelope::new(kind, handle(), payload).unwrap();
            let frame = envelope.encode().unwrap();
            prop_assert_eq!(Envelope::decode(&frame).unwrap(), envelope);
        }
    }
}
