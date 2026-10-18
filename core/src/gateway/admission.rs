//! Per-instance call admission shared with the trusted process owner.
use super::GatewayError;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

const DRAIN_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Default)]
struct State {
    suspended: bool,
    draining: bool,
    active: usize,
}
struct Inner {
    state: Mutex<State>,
    stop: watch::Sender<bool>,
}

#[derive(Clone)]
pub(crate) struct InstanceAdmission(Arc<Inner>);

impl InstanceAdmission {
    pub(crate) fn new(stop: watch::Sender<bool>) -> Self {
        Self(Arc::new(Inner {
            state: Mutex::new(State::default()),
            stop,
        }))
    }

    pub(crate) fn admit(&self) -> Result<CallGuard, GatewayError> {
        let mut state = self.0.state.lock().map_err(|_| GatewayError::Unavailable)?;
        if state.suspended || state.draining || *self.0.stop.borrow() {
            return Err(GatewayError::Unavailable);
        }
        state.active = state
            .active
            .checked_add(1)
            .ok_or(GatewayError::Unavailable)?;
        Ok(CallGuard(self.clone()))
    }

    /// Reversible only until the logical commit. Already admitted calls keep
    /// their guard and may finish while the installer's gate remains held.
    pub(crate) fn suspend(&self) -> Result<(), GatewayError> {
        self.0
            .state
            .lock()
            .map_err(|_| GatewayError::Unavailable)?
            .suspended = true;
        Ok(())
    }

    pub(crate) fn resume(&self) -> Result<(), GatewayError> {
        let mut state = self.0.state.lock().map_err(|_| GatewayError::Unavailable)?;
        if !state.draining {
            state.suspended = false;
        }
        Ok(())
    }

    /// Terminal for this instance: idle stops immediately; in-flight calls
    /// stop on their final guard or at the normative 30-second deadline.
    pub(crate) fn drain(&self) -> Result<(), GatewayError> {
        self.drain_until(tokio::time::Instant::now() + DRAIN_LIMIT)
    }

    fn drain_until(&self, deadline: tokio::time::Instant) -> Result<(), GatewayError> {
        let mut state = self.0.state.lock().map_err(|_| GatewayError::Unavailable)?;
        state.suspended = true;
        if state.draining {
            return Ok(());
        }
        state.draining = true;
        if state.active == 0 {
            self.0.stop.send_replace(true);
        } else {
            let stop = self.0.stop.clone();
            tokio::spawn(async move {
                tokio::time::sleep_until(deadline).await;
                stop.send_replace(true);
            });
        }
        Ok(())
    }
}

pub(crate) struct CallGuard(InstanceAdmission);
impl Drop for CallGuard {
    fn drop(&mut self) {
        match self.0.0.state.lock() {
            Ok(mut state) => {
                state.active -= 1;
                if state.draining && state.active == 0 {
                    self.0.0.stop.send_replace(true);
                }
            }
            Err(_) => {
                self.0.0.stop.send_replace(true);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn suspension_preserves_calls_and_drain_is_terminal_until_last_guard() {
        let (stop, stopped) = watch::channel(false);
        let admission = InstanceAdmission::new(stop);
        let first = admission.admit().unwrap();
        let second = admission.admit().unwrap();
        admission.suspend().unwrap();
        assert!(admission.admit().is_err());
        assert!(!*stopped.borrow());
        admission.resume().unwrap();
        drop(admission.admit().unwrap());
        admission.drain().unwrap();
        admission.resume().unwrap();
        assert!(admission.admit().is_err());
        drop(first);
        assert!(!*stopped.borrow());
        drop(second);
        assert!(*stopped.borrow());
    }

    #[tokio::test]
    async fn deadline_stops_even_if_an_admitted_call_has_not_returned() {
        let (stop, mut stopped) = watch::channel(false);
        let admission = InstanceAdmission::new(stop);
        let _call = admission.admit().unwrap();
        admission.drain_until(tokio::time::Instant::now()).unwrap();
        stopped.changed().await.unwrap();
        assert!(*stopped.borrow());
        assert!(admission.admit().is_err());
    }
}
