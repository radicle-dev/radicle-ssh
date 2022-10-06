use std;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, RwLock};
use std::thread::sleep;
use std::time::{Duration, SystemTime};

use byteorder::{BigEndian, ByteOrder};
use cryptovec::CryptoVec;
use encoding::{Encoding, Position, Reader};
use thiserror::Error;

use super::msg;
use super::Constraint;
use crate::key::Private;

type InnerKeyStore<K> = Arc<RwLock<HashMap<Vec<u8>, (Arc<K>, SystemTime, Vec<Constraint>)>>>;
struct KeyStore<Key>(InnerKeyStore<Key>);

// NOTE: need to implement this since the derived version will require `Key: Clone` which is unecessary.
impl<Key> Clone for KeyStore<Key> {
    fn clone(&self) -> Self {
        KeyStore(self.0.clone())
    }
}

#[derive(Clone)]
struct Lock(Arc<RwLock<CryptoVec>>);

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Encoding(#[from] encoding::Error),

    #[error(transparent)]
    Private(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[allow(missing_docs)]
#[derive(Debug)]
pub enum ServerError<E> {
    E(E),
    Error(Error),
}

pub trait Agent<Key>: Clone + Send + 'static {
    fn confirm(self, _pk: Arc<Key>) -> (Self, bool) {
        (self, true)
    }
}

/// The main entry point for running a server, where `Self` is the type of stream that the server is backed by.
pub trait ServerStream
where
    Self: Sized + Send + Sync + Unpin + 'static,
{
    type Error;

    fn serve<K, L, A>(listener: L, agent: A) -> Result<(), Self::Error>
    where
        K: Private + Send + Sync + 'static,
        K::Error: std::error::Error + Send + Sync + 'static,
        L: Iterator<Item = Result<Self, Self::Error>> + Send + Unpin,
        A: Agent<K> + Send + Sync + 'static;
}

/// A helper trait for revoking a key in an asynchronous manner.
///
/// The revoking should be done on a spawned thread, however, since we are avoiding
/// committing to a runtime we use this trait to allow for different `spawn` and `sleep` implementations.
///
/// Any implementation should just be of the form:
/// ```txt
/// spawn(async move { sleep(duration); revoke_key(keys, blob, now) });
/// ```
///
/// Where `revoke_key` is the function defined as [`crate::server::revoke_key`].
trait Revoker<K> {
    fn revoke(&self, keys: KeyStore<K>, blob: Vec<u8>, now: SystemTime, duration: Duration);
}

fn revoke_key<K>(keys: KeyStore<K>, blob: Vec<u8>, now: SystemTime) {
    let mut keys = keys.0.write().unwrap();
    let delete = if let Some(&(_, time, _)) = keys.get(&blob) {
        time == now
    } else {
        false
    };
    if delete {
        keys.remove(&blob);
    }
}

impl<K> Agent<K> for () {
    fn confirm(self, _: Arc<K>) -> (Self, bool) {
        (self, true)
    }
}

struct Connection<Key, A: Agent<Key>> {
    lock: Lock,
    keys: KeyStore<Key>,
    agent: Option<A>,
    revoker: Box<dyn Revoker<Key> + Send + Sync + 'static>,
    buf: CryptoVec,
}

impl<K, A> Connection<K, A>
where
    K: Private + Send + Sync + 'static,
    K::Error: std::error::Error + Send + Sync + 'static,
    A: Agent<K> + Send + 'static,
{
    pub fn respond(&mut self, writebuf: &mut CryptoVec) -> Result<(), Error> {
        let is_locked = {
            if let Ok(password) = self.lock.0.read() {
                !password.is_empty()
            } else {
                true
            }
        };
        writebuf.extend(&[0, 0, 0, 0]);
        let mut r = self.buf.reader(0);
        match r.read_byte() {
            Ok(11) if !is_locked => {
                // request identities
                if let Ok(keys) = self.keys.0.read() {
                    writebuf.push(msg::IDENTITIES_ANSWER);
                    writebuf.push_u32_be(keys.len() as u32);
                    for (k, _) in keys.iter() {
                        writebuf.extend_ssh_string(k);
                        writebuf.extend_ssh_string(b"");
                    }
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(13) if !is_locked => {
                // sign request
                let agent = self.agent.take().unwrap();
                let (agent, signed) = self.try_sign(agent, r, writebuf)?;
                self.agent = Some(agent);
                if signed {
                    return Ok(());
                } else {
                    writebuf.resize(4);
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(17) if !is_locked => {
                // add identity
                if let Ok(true) = self.add_key(r, false, writebuf) {
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(18) if !is_locked => {
                // remove identity
                if let Ok(true) = self.remove_identity(r) {
                    writebuf.push(msg::SUCCESS)
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(19) if !is_locked => {
                // remove all identities
                if let Ok(mut keys) = self.keys.0.write() {
                    keys.clear();
                    writebuf.push(msg::SUCCESS)
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(22) if !is_locked => {
                // lock
                if let Ok(()) = self.lock(r) {
                    writebuf.push(msg::SUCCESS)
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(23) if is_locked => {
                // unlock
                if let Ok(true) = self.unlock(r) {
                    writebuf.push(msg::SUCCESS)
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(25) if !is_locked => {
                // add identity constrained
                if let Ok(true) = self.add_key(r, true, writebuf) {
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            _ => {
                // Message not understood
                writebuf.push(msg::FAILURE)
            }
        }
        let len = writebuf.len() - 4;
        BigEndian::write_u32(&mut writebuf[0..], len as u32);
        Ok(())
    }

    fn lock(&self, mut r: Position) -> Result<(), Error> {
        let password = r.read_string()?;
        let mut lock = self.lock.0.write().unwrap();
        lock.extend(password);
        Ok(())
    }

    fn unlock(&self, mut r: Position) -> Result<bool, Error> {
        let password = r.read_string()?;
        let mut lock = self.lock.0.write().unwrap();
        if &lock[0..] == password {
            lock.clear();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn remove_identity(&self, mut r: Position) -> Result<bool, Error> {
        if let Ok(mut keys) = self.keys.0.write() {
            if keys.remove(r.read_string()?).is_some() {
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    fn add_key<'a>(
        &self,
        mut r: Position<'a>,
        constrained: bool,
        writebuf: &mut CryptoVec,
    ) -> Result<bool, Error> {
        let (blob, key) = match K::read(&mut r).map_err(|err| Error::Private(Box::new(err)))? {
            Some((blob, key)) => (blob, key),
            None => return Ok(false),
        };
        writebuf.push(msg::SUCCESS);
        let mut w = self.keys.0.write().unwrap();
        let now = SystemTime::now();
        if constrained {
            let mut c = Vec::new();
            while let Ok(t) = r.read_byte() {
                if t == msg::CONSTRAIN_LIFETIME {
                    let seconds = r.read_u32()?;
                    c.push(Constraint::KeyLifetime { seconds });
                    let blob = blob.clone();
                    let keys = self.keys.clone();
                    let duration = Duration::from_secs(seconds as u64);
                    self.revoker.revoke(keys, blob, now, duration);
                } else if t == msg::CONSTRAIN_CONFIRM {
                    c.push(Constraint::Confirm)
                } else {
                    return Ok(false);
                }
            }
            w.insert(blob, (Arc::new(key), now, c));
        } else {
            w.insert(blob, (Arc::new(key), now, Vec::new()));
        }
        Ok(true)
    }

    fn try_sign<'a>(
        &self,
        agent: A,
        mut r: Position<'a>,
        writebuf: &mut CryptoVec,
    ) -> Result<(A, bool), Error> {
        let mut needs_confirm = false;
        let key = {
            let blob = r.read_string()?;
            let k = self.keys.0.read().unwrap();
            if let Some(&(ref key, _, ref constraints)) = k.get(blob) {
                if constraints.iter().any(|c| *c == Constraint::Confirm) {
                    needs_confirm = true;
                }
                key.clone()
            } else {
                return Ok((agent, false));
            }
        };
        let agent = if needs_confirm {
            let (agent, ok) = agent.confirm(key.clone());
            if !ok {
                return Ok((agent, false));
            }
            agent
        } else {
            agent
        };
        writebuf.push(msg::SIGN_RESPONSE);
        let data = r.read_string()?;
        key.write_signature(writebuf, data)
            .map_err(|err| Error::Private(Box::new(err)))?;
        let len = writebuf.len();
        BigEndian::write_u32(writebuf, (len - 4) as u32);

        Ok((agent, true))
    }
}

pub struct Revoke {}

impl<K> Revoker<K> for Revoke
where
    K: Send + Sync + 'static,
{
    fn revoke(&self, keys: KeyStore<K>, blob: Vec<u8>, now: SystemTime, duration: Duration) {
        sleep(duration);
        revoke_key(keys, blob, now)
    }
}

#[cfg(unix)]
impl ServerStream for UnixStream {
    type Error = std::io::Error;

    fn serve<K, L, A>(mut listener: L, agent: A) -> Result<(), Self::Error>
    where
        K: Private + Send + Sync + 'static,
        K::Error: std::error::Error + Send + Sync + 'static,
        L: Iterator<Item = Result<Self, Self::Error>> + Send + Unpin,
        A: Agent<K> + Send + Sync + 'static,
    {
        let keys = KeyStore(Arc::new(RwLock::new(HashMap::new())));
        let lock = Lock(Arc::new(RwLock::new(CryptoVec::new())));
        while let Some(Ok(stream)) = listener.next() {
            let mut buf = CryptoVec::new();
            buf.resize(4);
            let _ = run(
                Connection {
                    lock: lock.clone(),
                    keys: keys.clone(),
                    agent: Some(agent.clone()),
                    revoker: Box::new(Revoke {}),
                    buf: CryptoVec::new(),
                },
                stream,
            );
        }
        Ok(())
    }
}

#[cfg(not(unix))]
impl ServerStream for TcpStream {
    type Error = std::io::Error;

    fn serve<K, L, A>(_: L, _: A) -> Result<(), Self::Error>
    where
        K: Private + Send + Sync + 'static,
        K::Error: std::error::Error + Send + Sync + 'static,
        L: Stream<Item = Result<Self, Self::Error>> + Send + Unpin,
        A: Agent<K> + Send + Sync + 'static,
    {
        use std::io::{Error, ErrorKind};

        Err(Error::new(
            ErrorKind::Unsupported,
            "non-unix systems are not supported",
        ))
    }
}

fn run<S, K, A>(mut connection: Connection<K, A>, mut stream: S) -> Result<(), Error>
where
    S: Read + Write + Send + Unpin + 'static,
    K: Private + Send + Sync + 'static,
    K::Error: std::error::Error + Send + Sync + 'static,
    A: Agent<K> + Send + 'static,
{
    let mut writebuf = CryptoVec::new();
    loop {
        // Reading the length
        connection.buf.clear();
        connection.buf.resize(4);
        stream.read_exact(&mut connection.buf)?;
        // Reading the rest of the buffer
        let len = BigEndian::read_u32(&connection.buf) as usize;
        connection.buf.clear();
        connection.buf.resize(len);
        stream.read_exact(&mut connection.buf)?;
        // respond
        writebuf.clear();
        connection.respond(&mut writebuf)?;
        stream.write_all(&writebuf)?;
        stream.flush()?
    }
}
