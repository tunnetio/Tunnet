//! JNI surface for the Android app: `io.tunnet.android.TunnetNative`.
//!
//! Mechanical marshalling only. Every call returns a JSON string so the Kotlin
//! side needs no generated types and errors cross the boundary as data rather
//! than as Java exceptions thrown from native code:
//!
//! ```json
//! {"ok": true,  "data": { ... }}
//! {"ok": false, "error": "human readable reason"}
//! ```
//!
//! All of these block. Kotlin must call them off the main thread.

use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::{Mutex, Once};

use anyhow::{Context, Result, bail};
use jni::JNIEnv;
use jni::objects::{GlobalRef, JClass, JObject, JString};
use jni::{JavaVM, sys::jstring};
use tunnet_agent::android_tun::{self, TunProvider, TunRequest};
use tunnet_common::local_api::NetworkJoinRequest;

use crate::session::AgentSession;

/// The one embedded agent. A process hosts a single VPN session, so a single
/// session is the honest model; a second `start` is a bug, not a use case.
static SESSION: Mutex<Option<AgentSession>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Android platform context
// ---------------------------------------------------------------------------

/// Register the JVM `Context` with `ndk-context`, exactly once per process.
///
/// Rust code in the tree resolves TLS through the platform verifier on Android
/// (`hickory-resolver`'s `rustls-platform-verifier` feature, and iroh's DNS
/// stack): loading the platform trust store needs the JVM `Context`, fetched
/// via `ndk_context::android_context()`, which PANICS with "android context
/// was not initialized" when nobody registered it. The release profile aborts
/// on panic, so without this call the app process dies mid-join.
///
/// `ndk-context` also asserts on double initialization, hence the `Once`: the
/// user can stop and restart the agent, but the process keeps its context.
static INIT_ANDROID_CONTEXT: Once = Once::new();

fn init_android_context(env: &mut JNIEnv, service: &JObject) -> Result<()> {
    let vm = env.get_java_vm().context("obtain JavaVM")?;
    // A strong global ref: the registered context object must stay alive as long
    // as the process, and a local ref would be freed on return.
    let service_ref = env
        .new_global_ref(service)
        .context("pin VpnService reference")?;
    INIT_ANDROID_CONTEXT.call_once(|| {
        // SAFETY: the JavaVM pointer is valid for the process lifetime, and the
        // context object is held by `service_ref` for the same lifetime, so the
        // pointers stay valid for however long ndk-context holds them. Called
        // exactly once, satisfying the crate's own contract.
        unsafe {
            ndk_context::initialize_android_context(
                vm.get_java_vm_pointer().cast(),
                service_ref.as_obj().as_raw().cast(),
            );
        }
        // Leaking the ref is deliberate: ndk-context needs the context for the
        // rest of the process, so it must never be freed. The same object is
        // pinned again for the TunProvider below, so this is one deliberate
        // lifetime extension, not a leak per start.
        std::mem::forget(service_ref);
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// Tunnel establishment: agent -> app
// ---------------------------------------------------------------------------

/// Bridges [`TunProvider`] to `TunnetVpnService.establishTun`.
struct JvmTunProvider {
    vm: JavaVM,
    service: GlobalRef,
}

impl TunProvider for JvmTunProvider {
    fn establish(&self, request: TunRequest) -> Result<OwnedFd> {
        // The data plane establishes from a tokio worker thread, which the JVM
        // has never seen, so it must be attached before any JNI call.
        let mut env = self
            .vm
            .attach_current_thread()
            .context("attach data-plane thread to the JVM")?;

        let ipv4 = env
            .new_string(request.ipv4.to_string())
            .context("marshal tunnel address")?;

        let fd = env
            .call_method(
                &self.service,
                "establishTun",
                "(Ljava/lang/String;II)I",
                &[
                    (&ipv4).into(),
                    jni::objects::JValue::Int(i32::from(request.prefix)),
                    jni::objects::JValue::Int(i32::from(request.mtu)),
                ],
            )
            .and_then(|v| v.i());

        // A Java-side exception leaves the thread in a pending-exception state;
        // clear it or the next JNI call on this thread aborts the process.
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
            bail!("VpnService.establishTun threw");
        }

        let fd = fd.context("call VpnService.establishTun")?;
        if fd < 0 {
            bail!(
                "VpnService could not establish a tunnel (returned {fd}); \
                 permission was likely revoked"
            );
        }

        // SAFETY: the Kotlin side returns ParcelFileDescriptor.detachFd(), so
        // ownership has transferred to us and nothing else will close it.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

// ---------------------------------------------------------------------------
// JSON envelopes
// ---------------------------------------------------------------------------

fn ok_json(data: serde_json::Value) -> String {
    serde_json::json!({ "ok": true, "data": data }).to_string()
}

fn err_json(error: &anyhow::Error) -> String {
    // `{:#}` includes the context chain, which is what makes a failure
    // diagnosable from a phone screen.
    serde_json::json!({ "ok": false, "error": format!("{error:#}") }).to_string()
}

fn envelope(result: Result<serde_json::Value>) -> String {
    match result {
        Ok(data) => ok_json(data),
        Err(e) => {
            tracing::warn!(error = ?e, "native call failed");
            err_json(&e)
        }
    }
}

/// Marshal a Rust `String` back to the JVM, falling back to a null pointer only
/// if even the error envelope cannot be allocated.
fn to_jstring(env: &mut JNIEnv, value: String) -> jstring {
    match env.new_string(value) {
        Ok(s) => s.into_raw(),
        Err(_) => JObject::null().into_raw(),
    }
}

fn read_string(env: &mut JNIEnv, value: &JString) -> Result<String> {
    Ok(env
        .get_string(value)
        .context("read Java string argument")?
        .into())
}

/// Run `f` against the running session, or fail with a clear reason.
fn with_session<T>(f: impl FnOnce(&AgentSession) -> Result<T>) -> Result<T> {
    let guard = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    let session = guard
        .as_ref()
        .context("agent is not running; call nativeStart first")?;
    f(session)
}

fn json_of<T: serde::Serialize>(value: T) -> Result<serde_json::Value> {
    serde_json::to_value(value).context("serialize response")
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

/// Start the embedded agent. `service` must implement
/// `int establishTun(String ipv4, int prefix, int mtu)`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_tunnet_android_TunnetNative_nativeStart(
    mut env: JNIEnv,
    _class: JClass,
    state_dir: JString,
    device_name: JString,
    service: JObject,
) -> jstring {
    let result = (|| -> Result<serde_json::Value> {
        init_logging();

        let state_dir = read_string(&mut env, &state_dir)?;
        let device_name = read_string(&mut env, &device_name)?;

        let mut guard = SESSION.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            bail!("agent is already running");
        }

        // Before anything that might touch TLS: platform-verifier code paths
        // fetch this context lazily, including inside the join flow itself.
        init_android_context(&mut env, &service)?;

        // Install the tunnel bridge before starting: the agent establishes the
        // TUN during startup, so a provider registered afterwards is too late.
        let provider = JvmTunProvider {
            vm: env.get_java_vm().context("obtain JavaVM")?,
            service: env
                .new_global_ref(service)
                .context("pin VpnService reference")?,
        };
        android_tun::set_provider(Box::new(provider));

        match AgentSession::start(&state_dir, &device_name) {
            Ok(session) => {
                *guard = Some(session);
                Ok(serde_json::json!({ "state_dir": state_dir, "hostname": device_name }))
            }
            Err(e) => {
                // Leaving a live provider behind would let a dead agent
                // establish a tunnel on a later callback.
                android_tun::clear_provider();
                Err(e)
            }
        }
    })();

    let payload = envelope(result);
    to_jstring(&mut env, payload)
}

/// Stop the agent and tear the tunnel down. Idempotent.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_tunnet_android_TunnetNative_nativeStop(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let session = {
        let mut guard = SESSION.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };
    android_tun::clear_provider();

    let stopped = session.is_some();
    if let Some(session) = session {
        session.stop();
    }

    let payload = ok_json(serde_json::json!({ "stopped": stopped }));
    to_jstring(&mut env, payload)
}

/// Node status: mode, endpoint id, networks, and whether the data plane is up.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_tunnet_android_TunnetNative_nativeStatus(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let result = with_session(|session| {
        let node = session
            .block_on(session.client().node())
            .context("query node status")?;
        json_of(node)
    });

    let payload = envelope(result);
    to_jstring(&mut env, payload)
}

/// Join a Direct network with an invite code.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_tunnet_android_TunnetNative_nativeJoin(
    mut env: JNIEnv,
    _class: JClass,
    invite_code: JString,
    hostname: JString,
) -> jstring {
    let result = (|| -> Result<serde_json::Value> {
        let invite_code = read_string(&mut env, &invite_code)?;
        let hostname = read_string(&mut env, &hostname)?;
        if invite_code.trim().is_empty() {
            bail!("invite code is empty");
        }

        let request = NetworkJoinRequest {
            invite_code: invite_code.trim().to_string(),
            hostname: Some(hostname).filter(|h| !h.trim().is_empty()),
            // The phone is joining someone else's network and cannot answer a
            // firewall prompt mid-join, so accept the network's policy.
            auto_accept_firewall: true,
            no_encrypt_state: false,
        };

        with_session(|session| {
            let response = session
                .block_on(session.client().network_join(&request))
                .context("join network")?;
            json_of(response)
        })
    })();

    let payload = envelope(result);
    to_jstring(&mut env, payload)
}

/// Peers of `network_id`, for the peer list.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_tunnet_android_TunnetNative_nativePeers(
    mut env: JNIEnv,
    _class: JClass,
    network_id: JString,
) -> jstring {
    let result = (|| -> Result<serde_json::Value> {
        let network_id = read_string(&mut env, &network_id)?;
        with_session(|session| {
            let peers = session
                .block_on(session.client().network_peers(&network_id))
                .context("query peers")?;
            json_of(peers)
        })
    })();

    let payload = envelope(result);
    to_jstring(&mut env, payload)
}

/// Bring the data plane up (establishes a tunnel through the provider).
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_tunnet_android_TunnetNative_nativeUp(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let result = with_session(|session| {
        let response = session
            .block_on(session.client().data_plane_up())
            .context("bring data plane up")?;
        json_of(response)
    });

    let payload = envelope(result);
    to_jstring(&mut env, payload)
}

/// Take the data plane down without stopping the agent.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_tunnet_android_TunnetNative_nativeDown(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let result = with_session(|session| {
        let response = session
            .block_on(session.client().data_plane_down())
            .context("bring data plane down")?;
        json_of(response)
    });

    let payload = envelope(result);
    to_jstring(&mut env, payload)
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

/// Route `tracing` into logcat once, so `adb logcat -s tunnet` shows agent logs.
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
