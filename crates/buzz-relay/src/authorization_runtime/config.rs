//! Sole provider-free runtime configuration document.

use std::collections::BTreeSet;
use std::time::Duration;

use buzz_auth::{
    AuthorizationEventCapacityPolicy, CanonicalVerifierPolicy, NipFiMode, RouteCapability,
};
use serde::Deserialize;
use url::Url;

use super::RuntimeAuthorizationError;

/// Sole environment variable carrying the NIP-FI V1 configuration document.
pub const CONFIG_ENV: &str = "BUZZ_NIP_FI_V1_CONFIG_JSON";

const MAX_LEASE_SECONDS: u64 = 3_600;
const MAX_DELEGATION_SECONDS: u64 = 3_600;

/// Closed runtime mode after emergency-denial precedence is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFreeRuntimeMode {
    /// Configuration is absent and protected composition is not installed.
    Off,
    /// Complete provider-free protected composition is required.
    Enforce,
    /// Emergency denial overrides every configured protected capability.
    DenyProtected,
}

impl From<ProviderFreeRuntimeMode> for NipFiMode {
    fn from(mode: ProviderFreeRuntimeMode) -> Self {
        match mode {
            ProviderFreeRuntimeMode::Off => Self::Off,
            ProviderFreeRuntimeMode::Enforce => Self::Enforce,
            ProviderFreeRuntimeMode::DenyProtected => Self::DenyProtected,
        }
    }
}

/// HTTPS source for the canonical verifier's rotating keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwksSourceConfig {
    /// Fetch a JWKS document directly.
    JwksUri(Url),
    /// Resolve `jwks_uri` from an issuer-matched discovery document.
    DiscoveryUri(Url),
}

impl JwksSourceConfig {
    /// Configured HTTPS endpoint.
    pub const fn endpoint(&self) -> &Url {
        match self {
            Self::JwksUri(uri) | Self::DiscoveryUri(uri) => uri,
        }
    }
}

/// Explicit delegation policy. Disabled is the default and has no authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationConfig {
    /// Delegated authorization is unavailable.
    Disabled,
    /// Only the listed capabilities may be delegated for the finite bound.
    Enabled {
        /// Closed capability allow-list.
        capabilities: BTreeSet<RouteCapability>,
        /// Maximum delegated lifetime, further bounded by every lease edge.
        maximum_lifetime: Duration,
    },
}

/// Complete enabled-mode configuration independent of storage adapters.
#[derive(Clone)]
pub struct EnforceRuntimeConfig {
    verifier_policy: CanonicalVerifierPolicy,
    issuer: String,
    jwks_source: JwksSourceConfig,
    lease_maximum: Duration,
    policy_revision: u64,
    audit_capacity: AuthorizationEventCapacityPolicy,
    delegation: DelegationConfig,
    transport: serde_json::Map<String, serde_json::Value>,
    enrollment: serde_json::Map<String, serde_json::Value>,
    restore: serde_json::Map<String, serde_json::Value>,
}

impl EnforceRuntimeConfig {
    /// Stable verifier policy constructed from the sole document.
    pub const fn verifier_policy(&self) -> &CanonicalVerifierPolicy {
        &self.verifier_policy
    }

    /// Expected issuer used to bind discovery metadata.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Rotating key source.
    pub const fn jwks_source(&self) -> &JwksSourceConfig {
        &self.jwks_source
    }

    /// Installation lease ceiling.
    pub const fn lease_maximum(&self) -> Duration {
        self.lease_maximum
    }

    /// Positive local policy revision.
    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }

    /// Immutable authorization-event capacity.
    pub const fn audit_capacity(&self) -> AuthorizationEventCapacityPolicy {
        self.audit_capacity
    }

    /// Explicit delegation policy.
    pub const fn delegation(&self) -> &DelegationConfig {
        &self.delegation
    }

    /// Opaque transport configuration reserved for the transport authority adapter.
    pub const fn transport_config(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.transport
    }

    /// Opaque enrollment configuration reserved for canonical admission.
    pub const fn enrollment_config(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.enrollment
    }

    /// Opaque restore backend configuration reserved for the restore adapter.
    pub const fn restore_config(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.restore
    }
}

impl std::fmt::Debug for EnforceRuntimeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EnforceRuntimeConfig([REDACTED])")
    }
}

/// Validated sole runtime configuration.
#[derive(Clone)]
pub struct ProviderFreeRuntimeConfig {
    mode: ProviderFreeRuntimeMode,
    enforce: Option<EnforceRuntimeConfig>,
}

impl ProviderFreeRuntimeConfig {
    /// Parse an optional JSON document. Absence is exactly Off.
    pub fn from_optional_json(raw: Option<&str>) -> Result<Self, RuntimeAuthorizationError> {
        let Some(raw) = raw else {
            return Ok(Self::off());
        };
        if raw.trim().is_empty() {
            return Err(RuntimeAuthorizationError::InvalidConfiguration);
        }
        let document: RuntimeDocument = serde_json::from_str(raw)
            .map_err(|_| RuntimeAuthorizationError::InvalidConfiguration)?;
        if document.deny_protected {
            return Ok(Self {
                mode: ProviderFreeRuntimeMode::DenyProtected,
                enforce: None,
            });
        }
        let enforce = document.validate_enforce()?;
        Ok(Self {
            mode: ProviderFreeRuntimeMode::Enforce,
            enforce: Some(enforce),
        })
    }

    /// Stock provider-free runtime default.
    pub const fn off() -> Self {
        Self {
            mode: ProviderFreeRuntimeMode::Off,
            enforce: None,
        }
    }

    /// Closed operating mode.
    pub const fn mode(&self) -> ProviderFreeRuntimeMode {
        self.mode
    }

    /// Complete enabled configuration, present only in Enforce mode.
    pub const fn enforce(&self) -> Option<&EnforceRuntimeConfig> {
        self.enforce.as_ref()
    }
}

impl std::fmt::Debug for ProviderFreeRuntimeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderFreeRuntimeConfig")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeDocument {
    #[serde(default)]
    deny_protected: bool,
    issuer: Option<String>,
    audience: Option<String>,
    #[serde(default = "default_subject_claim")]
    subject_claim: String,
    event_author_claim: Option<String>,
    #[serde(default)]
    clock_skew_seconds: u64,
    maximum_token_lifetime_seconds: Option<u64>,
    jwks: Option<JwksDocument>,
    lease: Option<LeaseDocument>,
    policy_revision: Option<u64>,
    audit: Option<AuditDocument>,
    transport: Option<serde_json::Map<String, serde_json::Value>>,
    enrollment: Option<serde_json::Map<String, serde_json::Value>>,
    restore: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    delegation: DelegationDocument,
}

impl RuntimeDocument {
    fn validate_enforce(self) -> Result<EnforceRuntimeConfig, RuntimeAuthorizationError> {
        let issuer = required_text(self.issuer)?;
        let audience = required_text(self.audience)?;
        let maximum_token_lifetime_seconds = self
            .maximum_token_lifetime_seconds
            .ok_or(RuntimeAuthorizationError::InvalidConfiguration)?;
        let verifier_policy = CanonicalVerifierPolicy::new(
            issuer.clone(),
            audience,
            self.subject_claim,
            self.event_author_claim,
            self.clock_skew_seconds,
            maximum_token_lifetime_seconds,
        )
        .map_err(|_| RuntimeAuthorizationError::InvalidConfiguration)?;
        let jwks_source = self
            .jwks
            .ok_or(RuntimeAuthorizationError::InvalidConfiguration)?
            .validate()?;
        let lease_maximum_seconds = self
            .lease
            .ok_or(RuntimeAuthorizationError::InvalidConfiguration)?
            .maximum_seconds;
        if lease_maximum_seconds == 0 || lease_maximum_seconds > MAX_LEASE_SECONDS {
            return Err(RuntimeAuthorizationError::InvalidConfiguration);
        }
        let policy_revision = self
            .policy_revision
            .filter(|revision| *revision > 0)
            .ok_or(RuntimeAuthorizationError::InvalidConfiguration)?;
        let audit = self
            .audit
            .ok_or(RuntimeAuthorizationError::InvalidConfiguration)?;
        let audit_capacity = AuthorizationEventCapacityPolicy::new(
            audit.max_events_per_domain,
            audit.max_bytes_per_domain,
            audit.max_envelope_bytes,
        )
        .map_err(|_| RuntimeAuthorizationError::InvalidConfiguration)?;
        let transport = required_nonempty_map(self.transport)?;
        let enrollment = required_nonempty_map(self.enrollment)?;
        let restore = required_nonempty_map(self.restore)?;
        let delegation = self.delegation.validate(lease_maximum_seconds)?;

        Ok(EnforceRuntimeConfig {
            verifier_policy,
            issuer,
            jwks_source,
            lease_maximum: Duration::from_secs(lease_maximum_seconds),
            policy_revision,
            audit_capacity,
            delegation,
            transport,
            enrollment,
            restore,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JwksDocument {
    jwks_uri: Option<String>,
    discovery_uri: Option<String>,
}

impl JwksDocument {
    fn validate(self) -> Result<JwksSourceConfig, RuntimeAuthorizationError> {
        match (self.jwks_uri, self.discovery_uri) {
            (Some(uri), None) => Ok(JwksSourceConfig::JwksUri(valid_https_url(&uri)?)),
            (None, Some(uri)) => Ok(JwksSourceConfig::DiscoveryUri(valid_https_url(&uri)?)),
            _ => Err(RuntimeAuthorizationError::InvalidConfiguration),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseDocument {
    maximum_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditDocument {
    max_events_per_domain: u64,
    max_bytes_per_domain: u64,
    max_envelope_bytes: u32,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegationDocument {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    capabilities: Vec<CapabilityDocument>,
    maximum_seconds: Option<u64>,
}

impl DelegationDocument {
    fn validate(
        self,
        lease_maximum_seconds: u64,
    ) -> Result<DelegationConfig, RuntimeAuthorizationError> {
        if !self.enabled {
            if !self.capabilities.is_empty() || self.maximum_seconds.is_some() {
                return Err(RuntimeAuthorizationError::InvalidConfiguration);
            }
            return Ok(DelegationConfig::Disabled);
        }
        let maximum_seconds = self
            .maximum_seconds
            .filter(|seconds| {
                *seconds > 0
                    && *seconds <= MAX_DELEGATION_SECONDS
                    && *seconds <= lease_maximum_seconds
            })
            .ok_or(RuntimeAuthorizationError::InvalidConfiguration)?;
        let capability_count = self.capabilities.len();
        let capabilities: BTreeSet<_> = self
            .capabilities
            .into_iter()
            .map(CapabilityDocument::into_capability)
            .collect();
        if capabilities.is_empty() || capabilities.len() != capability_count {
            return Err(RuntimeAuthorizationError::InvalidConfiguration);
        }
        Ok(DelegationConfig::Enabled {
            capabilities,
            maximum_lifetime: Duration::from_secs(maximum_seconds),
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum CapabilityDocument {
    MessagesRead,
    MessagesWrite,
    ChannelsRead,
    ChannelsWrite,
    AdminChannels,
    UsersRead,
    UsersWrite,
    AdminUsers,
    JobsRead,
    JobsWrite,
    SubscriptionsRead,
    SubscriptionsWrite,
    FilesRead,
    FilesWrite,
    ReposRead,
    ReposWrite,
    GitRead,
    GitWrite,
    GitStream,
    MediaRead,
    MediaWrite,
    Moderation,
    AudioJoin,
    AudioMedia,
    Discovery,
    BindingStatus,
    Enrollment,
    InviteMint,
    InviteClaim,
}

impl CapabilityDocument {
    const fn into_capability(self) -> RouteCapability {
        match self {
            Self::MessagesRead => RouteCapability::MessagesRead,
            Self::MessagesWrite => RouteCapability::MessagesWrite,
            Self::ChannelsRead => RouteCapability::ChannelsRead,
            Self::ChannelsWrite => RouteCapability::ChannelsWrite,
            Self::AdminChannels => RouteCapability::AdminChannels,
            Self::UsersRead => RouteCapability::UsersRead,
            Self::UsersWrite => RouteCapability::UsersWrite,
            Self::AdminUsers => RouteCapability::AdminUsers,
            Self::JobsRead => RouteCapability::JobsRead,
            Self::JobsWrite => RouteCapability::JobsWrite,
            Self::SubscriptionsRead => RouteCapability::SubscriptionsRead,
            Self::SubscriptionsWrite => RouteCapability::SubscriptionsWrite,
            Self::FilesRead => RouteCapability::FilesRead,
            Self::FilesWrite => RouteCapability::FilesWrite,
            Self::ReposRead => RouteCapability::ReposRead,
            Self::ReposWrite => RouteCapability::ReposWrite,
            Self::GitRead => RouteCapability::GitRead,
            Self::GitWrite => RouteCapability::GitWrite,
            Self::GitStream => RouteCapability::GitStream,
            Self::MediaRead => RouteCapability::MediaRead,
            Self::MediaWrite => RouteCapability::MediaWrite,
            Self::Moderation => RouteCapability::Moderation,
            Self::AudioJoin => RouteCapability::AudioJoin,
            Self::AudioMedia => RouteCapability::AudioMedia,
            Self::Discovery => RouteCapability::Discovery,
            Self::BindingStatus => RouteCapability::BindingStatus,
            Self::Enrollment => RouteCapability::Enrollment,
            Self::InviteMint => RouteCapability::InviteMint,
            Self::InviteClaim => RouteCapability::InviteClaim,
        }
    }
}

fn default_subject_claim() -> String {
    "sub".to_owned()
}

fn required_text(value: Option<String>) -> Result<String, RuntimeAuthorizationError> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(RuntimeAuthorizationError::InvalidConfiguration)
}

fn required_nonempty_map(
    value: Option<serde_json::Map<String, serde_json::Value>>,
) -> Result<serde_json::Map<String, serde_json::Value>, RuntimeAuthorizationError> {
    value
        .filter(|value| !value.is_empty())
        .ok_or(RuntimeAuthorizationError::InvalidConfiguration)
}

fn valid_https_url(raw: &str) -> Result<Url, RuntimeAuthorizationError> {
    let url = Url::parse(raw).map_err(|_| RuntimeAuthorizationError::InvalidConfiguration)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(RuntimeAuthorizationError::InvalidConfiguration);
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enforce_json(extra: &str) -> String {
        format!(
            r#"{{
                "issuer":"https://issuer.example",
                "audience":"buzz",
                "maximum_token_lifetime_seconds":300,
                "jwks":{{"jwks_uri":"https://issuer.example/keys"}},
                "lease":{{"maximum_seconds":120}},
                "policy_revision":1,
                "audit":{{"max_events_per_domain":100,"max_bytes_per_domain":65536,"max_envelope_bytes":4096}},
                "transport":{{"kind":"sealed_nostr_proof"}},
                "enrollment":{{"kind":"canonical_admission"}},
                "restore":{{"kind":"operation_manifest"}}
                {extra}
            }}"#
        )
    }

    #[test]
    fn absence_is_off_and_deny_overrides_incomplete_document() {
        assert_eq!(
            ProviderFreeRuntimeConfig::from_optional_json(None)
                .unwrap()
                .mode(),
            ProviderFreeRuntimeMode::Off
        );
        assert_eq!(
            ProviderFreeRuntimeConfig::from_optional_json(Some(r#"{"deny_protected":true}"#))
                .unwrap()
                .mode(),
            ProviderFreeRuntimeMode::DenyProtected
        );
    }

    #[test]
    fn enforce_requires_every_dependency_family() {
        let config =
            ProviderFreeRuntimeConfig::from_optional_json(Some(&enforce_json(""))).unwrap();
        assert_eq!(config.mode(), ProviderFreeRuntimeMode::Enforce);
        assert!(config.enforce().is_some());

        let mut missing_restore: serde_json::Value =
            serde_json::from_str(&enforce_json("")).unwrap();
        missing_restore.as_object_mut().unwrap().remove("restore");
        let missing_restore = serde_json::to_string(&missing_restore).unwrap();
        assert!(ProviderFreeRuntimeConfig::from_optional_json(Some(&missing_restore)).is_err());
    }

    #[test]
    fn delegation_is_disabled_by_default_and_finite_when_enabled() {
        let disabled =
            ProviderFreeRuntimeConfig::from_optional_json(Some(&enforce_json(""))).unwrap();
        assert_eq!(
            disabled.enforce().unwrap().delegation(),
            &DelegationConfig::Disabled
        );

        let enabled = ProviderFreeRuntimeConfig::from_optional_json(Some(&enforce_json(
            r#", "delegation":{"enabled":true,"capabilities":["git_read"],"maximum_seconds":60}"#,
        )))
        .unwrap();
        assert!(matches!(
            enabled.enforce().unwrap().delegation(),
            DelegationConfig::Enabled { .. }
        ));

        let unbounded =
            enforce_json(r#", "delegation":{"enabled":true,"capabilities":["git_read"]}"#);
        assert!(ProviderFreeRuntimeConfig::from_optional_json(Some(&unbounded)).is_err());
    }

    #[test]
    fn verifier_policy_identity_does_not_depend_on_key_source() {
        let direct =
            ProviderFreeRuntimeConfig::from_optional_json(Some(&enforce_json(""))).unwrap();
        let discovery_json = enforce_json("").replace(
            r#""jwks_uri":"https://issuer.example/keys""#,
            r#""discovery_uri":"https://issuer.example/.well-known/openid-configuration""#,
        );
        let discovery =
            ProviderFreeRuntimeConfig::from_optional_json(Some(&discovery_json)).unwrap();
        assert_eq!(
            direct.enforce().unwrap().verifier_policy().id(),
            discovery.enforce().unwrap().verifier_policy().id()
        );
    }
}
