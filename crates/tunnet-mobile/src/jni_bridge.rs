//! JNI surface for `io.tunnet.android.TunnetNative`.
//!
//! Commands return protobuf `NativeResult`. Snapshots are pushed as protobuf
//! `Snapshot` bytes through `SnapshotListener.onSnapshot`. Runtime/network
//! threads never wait on Java: encoded snapshots land in a latest-wins slot
//! and a dedicated delivery thread attaches to the JVM.
//!
//! Command calls still block. Kotlin must invoke them off the main thread.

use std::os::fd::{FromRawFd, OwnedFd};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::thread::JoinHandle;

use anyhow::{Context, Result, bail};
use jni::objects::{Global, JByteArray, JClass, JObject, JObjectArray, JString, JValue};
use jni::{Env, EnvUnowned, JavaVM, jni_sig, jni_str};
use tunnet_agent::android_tun::{self, TunProvider, TunRequest};
use tunnet_agent::{
    AgentError, AgentErrorKind, JoinRequest, LatestSlot, MulticastHost, PlatformSealer, SealError,
    SealErrorKind, WireNativeResult, clear_multicast_host, sanitize_hostname, set_multicast_host,
    set_platform_sealer,
};

use crate::session::AgentSession;

static SESSION: Mutex<Option<AgentSession>> = Mutex::new(None);
static LISTENER: Mutex<Option<PinnedListener>> = Mutex::new(None);
static LISTENER_EPOCH: AtomicU64 = AtomicU64::new(0);
static DELIVERY: Mutex<Option<Delivery>> = Mutex::new(None);

struct PinnedListener {
    obj: Arc<Global<JObject<'static>>>,
    epoch: u64,
}

struct Delivery {
    latest: Arc<LatestSlot>,
    thread: JoinHandle<()>,
}

/// Register the JVM `Context` with `ndk-context`, exactly once per process.
///
/// TLS through the platform verifier needs `ndk_context::android_context()`.
/// `ndk-context` asserts on double initialization, so this is `Once`: stop and
/// restart the agent, but keep the process context.
static INIT_ANDROID_CONTEXT: Once = Once::new();

struct LogAndDefault;

impl<T: Default, E: std::fmt::Display> jni::errors::ErrorPolicy<T, E> for LogAndDefault {
    type Captures<'unowned_env_local: 'native_method, 'native_method> = ();

    fn on_error<'unowned_env_local: 'native_method, 'native_method>(
        _env: &mut Env<'unowned_env_local>,
        _cap: &mut Self::Captures<'unowned_env_local, 'native_method>,
        err: E,
    ) -> jni::errors::Result<T> {
        tracing::error!(error = %err, "jni native method failed");
        Ok(T::default())
    }

    fn on_panic<'unowned_env_local: 'native_method, 'native_method>(
        _env: &mut Env<'unowned_env_local>,
        _captures: &mut Self::Captures<'unowned_env_local, 'native_method>,
        payload: Box<dyn std::any::Any + Send + 'static>,
    ) -> jni::errors::Result<T> {
        let msg = panic_message(&payload);
        tracing::error!(panic = %msg, "jni native method panicked");
        Ok(T::default())
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "native panic".into())
}

fn init_android_context(env: &mut Env, service: &JObject) -> Result<()> {
    let vm = env.get_java_vm().context("obtain JavaVM")?;

    // Pin the application context, not the Service: ndk-context keeps the
    // pointer for the process lifetime, and `stopSelf()` destroys the Service.
    let app_context = env
        .call_method(
            service,
            jni_str!("getApplicationContext"),
            jni_sig!("()Landroid/content/Context;"),
            &[],
        )
        .and_then(|v| v.l())
        .context("obtain application context")?;
    let app_ref = env
        .new_global_ref(&app_context)
        .context("pin application context")?;

    INIT_ANDROID_CONTEXT.call_once(|| {
        // SAFETY: JavaVM is process-lived. The application Context is held by
        // `app_ref` for the same lifetime. Called once.
        unsafe {
            ndk_context::initialize_android_context(vm.get_raw().cast(), app_ref.as_raw().cast());
        }
        std::mem::forget(app_ref);
    });
    Ok(())
}

struct JvmTunProvider {
    vm: JavaVM,
    service: Global<JObject<'static>>,
}

fn string_array<'a>(
    env: &mut Env<'a>,
    items: impl ExactSizeIterator<Item = String>,
) -> jni::errors::Result<JObjectArray<'a, JString<'a>>> {
    let empty = env.new_string("")?;
    let array = JObjectArray::<JString>::new(env, items.len(), &empty)?;
    for (index, item) in items.enumerate() {
        let value = env.new_string(&item)?;
        array.set_element(env, index, &value)?;
    }
    Ok(array)
}

impl TunProvider for JvmTunProvider {
    fn establish(&self, request: TunRequest) -> Result<OwnedFd> {
        let fd = self
            .vm
            .attach_current_thread(|env| -> jni::errors::Result<i32> {
                let addrs = string_array(env, request.addrs.iter().map(|a| a.to_string()))?;
                let routes = string_array(env, request.routes.iter().map(|r| r.to_string()))?;
                let dns = string_array(env, request.dns.iter().map(|d| d.to_string()))?;
                env.call_method(
                    &self.service,
                    jni_str!("establishTun"),
                    jni_sig!("([Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;IZZ)I"),
                    &[
                        JValue::from(&addrs),
                        JValue::from(&routes),
                        JValue::from(&dns),
                        JValue::Int(i32::from(request.mtu)),
                        JValue::Bool(request.allow_ipv6_passthrough),
                        JValue::Bool(request.inherit_underlying_metered),
                    ],
                )?
                .i()
            })
            .map_err(|e: jni::errors::Error| anyhow::anyhow!("VpnService.establishTun: {e}"))?;

        if fd < 0 {
            bail!(
                "VpnService could not establish a tunnel (returned {fd}); \
                 permission was likely revoked"
            );
        }

        // SAFETY: Kotlin returns ParcelFileDescriptor.detachFd(); ownership
        // transfers here and nothing else will close it.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

struct JvmPlatformSealer {
    vm: JavaVM,
    class: Global<JClass<'static>>,
}

fn seal_kind_from_code(code: i32) -> SealErrorKind {
    match code {
        1 => SealErrorKind::KeyUnavailable,
        2 => SealErrorKind::KeyInvalidated,
        3 => SealErrorKind::CiphertextInvalid,
        4 => SealErrorKind::DecryptFailed,
        5 => SealErrorKind::OperationFailed,
        6 => SealErrorKind::Unsupported,
        _ => SealErrorKind::OperationFailed,
    }
}

impl JvmPlatformSealer {
    fn invoke(&self, wrap: bool, input: &[u8]) -> Result<Vec<u8>, SealError> {
        let outcome = self
            .vm
            .attach_current_thread(|env| -> jni::errors::Result<SealOpJni> {
                let bytes = env.byte_array_from_slice(input)?;
                let raw = if wrap {
                    env.call_static_method(
                        &self.class,
                        jni_str!("wrap"),
                        jni_sig!("([B)Lio/tunnet/android/SealOp;"),
                        &[JValue::from(&bytes)],
                    )
                } else {
                    env.call_static_method(
                        &self.class,
                        jni_str!("unwrap"),
                        jni_sig!("([B)Lio/tunnet/android/SealOp;"),
                        &[JValue::from(&bytes)],
                    )
                }?
                .l()?;
                if raw.is_null() {
                    return Ok(SealOpJni {
                        kind: 5,
                        blob: Vec::new(),
                        message: "keystore returned null".into(),
                    });
                }
                let kind = env
                    .call_method(&raw, jni_str!("getKind"), jni_sig!("()I"), &[])?
                    .i()?;
                let message = {
                    let obj = env
                        .call_method(
                            &raw,
                            jni_str!("getMessage"),
                            jni_sig!("()Ljava/lang/String;"),
                            &[],
                        )?
                        .l()?;
                    if obj.is_null() {
                        String::new()
                    } else {
                        let as_string = unsafe { JString::from_raw(env, obj.as_raw()) };
                        as_string.try_to_string(env).unwrap_or_default()
                    }
                };
                let blob = {
                    let obj = env
                        .call_method(&raw, jni_str!("getBlob"), jni_sig!("()[B"), &[])?
                        .l()?;
                    if obj.is_null() {
                        Vec::new()
                    } else {
                        let array = unsafe { JByteArray::from_raw(env, obj.as_raw()) };
                        env.convert_byte_array(&array)?
                    }
                };
                Ok(SealOpJni {
                    kind,
                    blob,
                    message,
                })
            });
        let op = outcome
            .map_err(|_| SealError::new(SealErrorKind::OperationFailed, "keystore jni call"))?;
        if op.kind != 0 {
            return Err(SealError::new(seal_kind_from_code(op.kind), op.message));
        }
        Ok(op.blob)
    }
}

struct SealOpJni {
    kind: i32,
    blob: Vec<u8>,
    message: String,
}

impl PlatformSealer for JvmPlatformSealer {
    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        self.invoke(true, plaintext)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, SealError> {
        self.invoke(false, wrapped)
    }
}

fn install_sealer(env: &mut Env) -> Result<()> {
    let class = env
        .find_class(jni_str!("io/tunnet/android/TunnetKeystore"))
        .context("find TunnetKeystore")?;
    let class = env
        .new_global_ref(&class)
        .context("pin TunnetKeystore class")?;
    set_platform_sealer(Arc::new(JvmPlatformSealer {
        vm: env.get_java_vm().context("obtain JavaVM")?,
        class,
    }));
    Ok(())
}

fn ok_bytes() -> Vec<u8> {
    WireNativeResult::ok().to_vec()
}

fn err_anyhow(error: &anyhow::Error) -> Vec<u8> {
    tracing::warn!(error = ?error, "native call failed");
    WireNativeResult::err(AgentErrorKind::Internal, format!("{error:#}")).to_vec()
}

fn err_agent(err: &AgentError) -> Vec<u8> {
    WireNativeResult::err(err.kind, err.message.clone()).to_vec()
}

fn read_string(env: &Env, value: &JString<'_>) -> jni::errors::Result<String> {
    value.try_to_string(env)
}

fn command_runtime() -> Result<(tunnet_agent::AgentHandle, tokio::runtime::Handle)> {
    let guard = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    let session = guard
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("agent session is missing; call nativeStart first"))?;
    Ok((session.handle().clone(), session.runtime_handle()))
}

fn install_provider(env: &mut Env, service: &JObject) -> Result<()> {
    let provider = JvmTunProvider {
        vm: env.get_java_vm().context("obtain JavaVM")?,
        service: env
            .new_global_ref(service)
            .context("pin VpnService reference")?,
    };
    android_tun::set_provider(Box::new(provider));
    Ok(())
}

struct JvmMulticastHost {
    vm: JavaVM,
    service: Global<JObject<'static>>,
}

impl MulticastHost for JvmMulticastHost {
    fn set_held(&self, held: bool) {
        let result = self
            .vm
            .attach_current_thread(|env| -> jni::errors::Result<()> {
                env.call_method(
                    &self.service,
                    jni_str!("setMulticastDemand"),
                    jni_sig!("(Z)V"),
                    &[JValue::Bool(held)],
                )?;
                Ok(())
            });
        if let Err(e) = result {
            tracing::warn!(error = %e, "setMulticastDemand failed");
        }
    }
}

fn install_multicast_host(env: &mut Env, service: &JObject) -> Result<()> {
    let host = JvmMulticastHost {
        vm: env.get_java_vm().context("obtain JavaVM")?,
        service: env
            .new_global_ref(service)
            .context("pin VpnService multicast host")?,
    };
    set_multicast_host(Box::new(host));
    Ok(())
}

fn drop_host_bridges() {
    android_tun::clear_provider();
    clear_multicast_host();
}

/// Contract: one agent per process. A second call rebinds the TUN provider to
/// `service` and does not create another runtime.
fn attach_or_start(
    env: &mut Env,
    state_dir: &str,
    device_name: &str,
    service: &JObject,
) -> Result<()> {
    init_android_context(env, service)?;
    install_provider(env, service)?;
    install_multicast_host(env, service)?;
    install_sealer(env)?;

    let mut guard = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(session) = guard.as_ref() {
        tracing::info!("nativeStart rebound TUN provider; existing agent kept");
        start_delivery(env.get_java_vm()?, session.latest().clone())?;
        return Ok(());
    }

    match AgentSession::start(state_dir, device_name) {
        Ok(session) => {
            tracing::info!("nativeStart created agent runtime");
            start_delivery(env.get_java_vm()?, session.latest().clone())?;
            *guard = Some(session);
            Ok(())
        }
        Err(e) => {
            drop_host_bridges();
            Err(e)
        }
    }
}

fn stop_session() {
    let session = {
        let mut guard = SESSION.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };
    drop_host_bridges();
    if let Some(session) = session {
        session.stop();
    }
    stop_delivery();
}

fn start_delivery(vm: JavaVM, latest: Arc<LatestSlot>) -> Result<()> {
    let mut delivery = DELIVERY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(existing) = delivery.as_ref()
        && !existing.latest.is_closed()
    {
        return Ok(());
    }
    if let Some(old) = delivery.take() {
        old.latest.close();
        let _ = old.thread.join();
    }
    let slot = latest.clone();
    let thread = std::thread::Builder::new()
        .name("tunnet-snap".into())
        .spawn(move || {
            let mut seen = 0u64;
            while let Some((seq, bytes)) = slot.wait_after(seen) {
                seen = seq;
                let _ = catch_unwind(AssertUnwindSafe(|| push_snapshot(&vm, &bytes)));
            }
        })
        .context("snapshot delivery thread")?;
    *delivery = Some(Delivery { latest, thread });
    Ok(())
}

fn stop_delivery() {
    let mut delivery = DELIVERY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(old) = delivery.take() {
        old.latest.close();
        let _ = old.thread.join();
    }
}

fn push_snapshot(vm: &JavaVM, bytes: &[u8]) {
    let listener = {
        let g = LISTENER.lock().unwrap_or_else(|e| e.into_inner());
        g.as_ref().map(|l| (l.obj.clone(), l.epoch))
    };
    let Some((obj, epoch)) = listener else {
        return;
    };
    let _ = vm.attach_current_thread(|env| -> jni::errors::Result<()> {
        if LISTENER_EPOCH.load(Ordering::SeqCst) != epoch {
            return Ok(());
        }
        let array = env.byte_array_from_slice(bytes)?;
        env.call_method(
            obj.as_obj(),
            jni_str!("onSnapshot"),
            jni_sig!("([B)V"),
            &[JValue::from(&array)],
        )?;
        Ok(())
    });
}

fn deliver_current(env: &mut Env) -> jni::errors::Result<()> {
    let latest = {
        let g = DELIVERY.lock().unwrap_or_else(|e| e.into_inner());
        g.as_ref().map(|d| d.latest.clone())
    };
    let Some((_, bytes)) = latest.as_ref().and_then(|s| s.current()) else {
        return Ok(());
    };
    let listener = {
        let g = LISTENER.lock().unwrap_or_else(|e| e.into_inner());
        g.as_ref().map(|l| (l.obj.clone(), l.epoch))
    };
    let Some((obj, epoch)) = listener else {
        return Ok(());
    };
    if LISTENER_EPOCH.load(Ordering::SeqCst) != epoch {
        return Ok(());
    }
    let array = env.byte_array_from_slice(&bytes)?;
    env.call_method(
        obj.as_obj(),
        jni_str!("onSnapshot"),
        jni_sig!("([B)V"),
        &[JValue::from(&array)],
    )?;
    Ok(())
}

fn replace_listener(env: &mut Env, listener: &JObject) -> jni::errors::Result<()> {
    let epoch = LISTENER_EPOCH
        .fetch_add(1, Ordering::SeqCst)
        .wrapping_add(1);
    let mut g = LISTENER.lock().unwrap_or_else(|e| e.into_inner());
    *g = if listener.is_null() {
        None
    } else {
        Some(PinnedListener {
            obj: Arc::new(env.new_global_ref(listener)?),
            epoch,
        })
    };
    Ok(())
}

/// Start or attach the embedded agent.
///
/// `service` must implement `int establishTun(...)`.
///
/// Idempotent: a second start in this process rebinds the TUN provider to the
/// new Service and does not create a second runtime.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_tunnet_android_TunnetNative_nativeStart<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    state_dir: JString<'local>,
    device_name: JString<'local>,
    service: JObject<'local>,
) -> JByteArray<'local> {
    unowned
        .with_env(|env| -> jni::errors::Result<JByteArray> {
            init_logging();
            let bytes = (|| -> Result<Vec<u8>> {
                let state_dir = read_string(env, &state_dir).context("state dir")?;
                let device_name = read_string(env, &device_name).context("device name")?;
                attach_or_start(env, &state_dir, &device_name, &service)?;
                Ok(ok_bytes())
            })();
            match bytes {
                Ok(b) => env.byte_array_from_slice(&b),
                Err(e) => env.byte_array_from_slice(&err_anyhow(&e)),
            }
        })
        .resolve::<LogAndDefault>()
}

/// Stop the agent if it is running. Harmless when already stopped.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_tunnet_android_TunnetNative_nativeStop<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> JByteArray<'local> {
    unowned
        .with_env(|env| -> jni::errors::Result<JByteArray> {
            stop_session();
            env.byte_array_from_slice(&ok_bytes())
        })
        .resolve::<LogAndDefault>()
}

/// Drop the TUN provider for a destroyed Service without stopping the agent.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_tunnet_android_TunnetNative_nativeReleaseHost<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
) {
    unowned
        .with_env(|_env| -> jni::errors::Result<()> {
            drop_host_bridges();
            Ok(())
        })
        .resolve::<LogAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_tunnet_android_TunnetNative_nativeSetSnapshotListener<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    listener: JObject<'local>,
) {
    unowned
        .with_env(|env| -> jni::errors::Result<()> {
            replace_listener(env, &listener)?;
            if !listener.is_null() {
                deliver_current(env)?;
            }
            Ok(())
        })
        .resolve::<LogAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_tunnet_android_TunnetNative_nativeJoin<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    invite_code: JString<'local>,
    hostname: JString<'local>,
) -> JByteArray<'local> {
    unowned
        .with_env(|env| -> jni::errors::Result<JByteArray> {
            let invite_code = match read_string(env, &invite_code) {
                Ok(s) => s,
                Err(e) => {
                    return env.byte_array_from_slice(&err_anyhow(&anyhow::anyhow!(e)));
                }
            };
            let hostname = match read_string(env, &hostname) {
                Ok(s) => sanitize_hostname(&s),
                Err(e) => {
                    return env.byte_array_from_slice(&err_anyhow(&anyhow::anyhow!(e)));
                }
            };
            if invite_code.trim().is_empty() {
                return env.byte_array_from_slice(&err_agent(&AgentError::new(
                    AgentErrorKind::InvalidRequest,
                    "invite code is empty",
                )));
            }
            let request = JoinRequest {
                invite_code: invite_code.trim().to_string(),
                hostname: Some(hostname).filter(|h| !h.trim().is_empty()),
                auto_accept_firewall: true,
                no_encrypt_state: false,
            };
            let bytes = match command_runtime() {
                Err(e) => err_anyhow(&e),
                Ok((handle, rt)) => {
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    rt.spawn(async move {
                        let _ = tx.send(handle.join(request).await);
                    });
                    match rx.blocking_recv() {
                        Ok(Ok(_)) => ok_bytes(),
                        Ok(Err(e)) => err_agent(&e),
                        Err(_) => err_agent(&AgentError::new(
                            AgentErrorKind::Stopped,
                            "runtime is stopped",
                        )),
                    }
                }
            };
            env.byte_array_from_slice(&bytes)
        })
        .resolve::<LogAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_tunnet_android_TunnetNative_nativeSetLanAvailable<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    available: bool,
) {
    unowned
        .with_env(|_env| -> jni::errors::Result<()> {
            tunnet_agent::set_lan_available(available);
            Ok(())
        })
        .resolve::<LogAndDefault>()
}

fn init_logging() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let filter = tracing_subscriber::EnvFilter::new(
            "info,tunnet_agent=debug,tunnet_core=debug,tunnet_mobile=debug",
        );
        let Ok(layer) = tracing_android::layer("tunnet") else {
            return;
        };
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(layer)
            .try_init();
    });
}
