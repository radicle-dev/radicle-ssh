use cryptovec::CryptoVec;
use encoding::Position;

pub trait Signature: Sized {
    type Error;

    fn read(buf: &CryptoVec) -> Result<Self, Self::Error>;
}

pub trait Public: Sized {
    type Error;

    fn write_blob(&self, buf: &mut CryptoVec);
    fn read(reader: &mut Position) -> Result<Option<Self>, Self::Error>;
    fn hash(&self) -> u32;
}

pub trait Private: Sized {
    type Error;

    fn read(reader: &mut Position) -> Result<Option<(Vec<u8>, Self)>, Self::Error>;
    fn write(&self, buf: &mut CryptoVec) -> Result<(), Self::Error>;
    fn write_signature<Bytes: AsRef<[u8]>>(
        &self,
        buf: &mut CryptoVec,
        to_sign: Bytes,
    ) -> Result<(), Self::Error>;
}
