use crate::error::PostureError;
use crate::platform::Platform;
use crate::value::PostureValue;
use async_trait::async_trait;
use jiff::Timestamp;
use std::collections::HashMap;

/// Result of a single collector run.
#[derive(Debug, Clone)]
pub struct PostureAttributes {
    pub attributes: HashMap<String, PostureValue>,
    pub collected_at: Timestamp,
    pub collector_name: String,
    pub error: Option<String>,
}

impl PostureAttributes {
    pub fn new(collector_name: impl Into<String>) -> Self {
        Self {
            attributes: HashMap::new(),
            collected_at: Timestamp::now(),
            collector_name: collector_name.into(),
            error: None,
        }
    }

    pub fn with_attribute(mut self, key: impl Into<String>, value: PostureValue) -> Self {
        self.attributes.insert(key.into(), value);
        self
    }

    pub fn with_error(mut self, message: impl Into<String>) -> Self {
        self.error = Some(message.into());
        self
    }
}

/// Core trait for posture attribute collectors.
#[async_trait]
pub trait PostureCollector: Send + Sync {
    fn name(&self) -> &'static str;

    fn supported_platforms(&self) -> &[Platform];

    fn namespace(&self) -> &'static str;

    fn is_available(&self) -> bool {
        crate::platform::platform_supported(self.supported_platforms())
    }

    async fn collect(&self) -> Result<PostureAttributes, PostureError>;
}
