pub mod collector;
pub mod collectors;
pub mod engine;
pub mod error;
pub mod evaluate;
pub mod platform;
pub mod remediation;
pub mod score;
pub mod value;

pub use collector::{PostureAttributes, PostureCollector};
pub use engine::{
    CollectorStatus, PostureCollection, PostureEngine, PostureEngineConfig, PostureState,
    compute_state_hash,
};
pub use error::PostureError;
pub use evaluate::{
    PostureAssertion, PostureEvalSummary, PostureOp, PostureResult, evaluate_named_postures,
    evaluate_posture, parse_assertion, parse_assertions,
};
pub use platform::Platform;
pub use remediation::{
    RemediationMessage, format_remediation_messages, remediation_for_attribute,
    remediation_for_failures,
};
pub use score::{PostureScoringConfig, ScoreWeight, compute_posture_score, inject_posture_score};
pub use value::PostureValue;

// Re-export collector types for configuration.
pub use collectors::{
    AppCheckConfig, ApplicationCheckCollector, CustomScriptCollector, CustomScriptConfig,
    FileCheckCollector, FileCheckConfig,
};
