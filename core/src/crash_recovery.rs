//! ADR-039 trusted core inputs. These types are deliberately not deserializable
//! from Kernel Protocol requests. Reading a status never starts a process.
use crate::store::StoreError;
use std::{
    fs::File,
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecoveryKey {
    pub ext_id: String,
    pub key: String,
    pub session_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryStatus {
    Ready,
    Backoff { retry_after_ms: i64 },
    CrashLoop,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrashTime {
    pub boot_id: String,
    pub boottime_ms: i64,
    /// Diagnostic only; civil time never controls the window or deadline.
    pub unix_ms: i64,
}

pub trait CrashClock: Send + Sync + 'static {
    fn now(&self) -> Result<CrashTime, StoreError>;
}

pub struct LinuxCrashClock;
impl CrashClock for LinuxCrashClock {
    fn now(&self) -> Result<CrashTime, StoreError> {
        let mut bytes = Vec::new();
        File::open("/proc/sys/kernel/random/boot_id")?
            .take(65)
            .read_to_end(&mut bytes)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| StoreError::Clock)?;
        let boot_id = text.strip_suffix('\n').unwrap_or(text).to_owned();
        // SAFETY: clock_gettime fills a valid timespec buffer for Linux's
        // suspend-inclusive monotonic clock. No process data is inspected.
        let mut time: libc::timespec = unsafe { std::mem::zeroed() };
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if time.tv_sec < 0 || !(0..1_000_000_000).contains(&time.tv_nsec) {
            return Err(StoreError::Clock);
        }
        let boottime_ms = time
            .tv_sec
            .checked_mul(1000)
            .and_then(|value| value.checked_add(time.tv_nsec / 1_000_000))
            .ok_or(StoreError::Clock)?;
        let sample = CrashTime {
            boot_id,
            boottime_ms,
            unix_ms: match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(duration) => {
                    i64::try_from(duration.as_millis()).map_err(|_| StoreError::Clock)?
                }
                // A civil clock rollback across the epoch remains diagnostic;
                // it must not invalidate an otherwise valid BOOTTIME sample.
                Err(error) => i64::try_from(error.duration().as_millis())
                    .map_err(|_| StoreError::Clock)?
                    .checked_neg()
                    .ok_or(StoreError::Clock)?,
            },
        };
        sample.validate()?;
        Ok(sample)
    }
}

impl CrashTime {
    pub(crate) fn validate(&self) -> Result<(), StoreError> {
        if self.boottime_ms < 0 || !valid_boot_id(&self.boot_id) {
            return Err(StoreError::Clock);
        }
        Ok(())
    }
}
pub(crate) fn valid_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

#[derive(Clone, Debug)]
pub struct CrashStderr {
    pub blob: Option<String>,
    pub unavailable: bool,
}
impl CrashStderr {
    pub fn unavailable() -> Self {
        Self {
            blob: None,
            unavailable: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CrashObservation {
    pub recovery: RecoveryKey,
    pub instance_id: String,
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub stderr: CrashStderr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrashRecorded {
    pub recorded: bool,
    pub status: RecoveryStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryScope {
    Global,
    Session,
}

/// Caller resolves this selection from the validated lock while holding the
/// installer exclusion. None selects every session for this extension/key.
#[derive(Clone, Debug)]
pub struct ResetCrashes {
    pub ext_id: String,
    pub key: String,
    pub scope: RecoveryScope,
    pub session_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrashesReset {
    pub cleared: usize,
}
