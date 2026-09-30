// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The egress-policy listener filter names the filter chain a tunneled
//! connection belongs on, from what the inspectors before it found and the
//! rules the CONNECT leg answered with. See the README in this directory.

use envoy_proxy_dynamic_modules_rust_sdk::{
  abi::envoy_dynamic_module_type_on_listener_filter_status,
  declare_listener_filter_init_functions, envoy_log_trace, EnvoyListenerFilter,
  EnvoyListenerFilterConfig, ListenerFilter, ListenerFilterConfig,
};
use serde::Deserialize;

/// Filter state the CONNECT leg's ext_proc answer is copied into: the rules
/// that decide this connection's TLS, as JSON. The shape is fixed by
/// EgressPolicyMetadataNamespace in cmd/atenet/internal/router/extproc.
pub const ATE_POLICY_EGRESS: &[u8] = b"dev.ate.policy.egress";

/// Filter state this filter writes: the name of the chain the connection
/// belongs on. The listener's filter_chain_matcher selects on it.
pub const ATE_EGRESS_FILTER_CHAIN: &[u8] = b"dev.ate.egress.filter_chain";

/// Verdict for TLS an https rule allows: terminated and decided per request.
pub const ATE_EGRESS_FILTER_CHAIN_MITM: &str = "mitm";

/// Verdict for anything that is not TLS: decided per request in the clear.
pub const ATE_EGRESS_FILTER_CHAIN_CLEARTEXT: &str = "cleartext";

/// Verdict for a connection no rule allows. No chain has this name, so the
/// connection is closed.
pub const ATE_EGRESS_FILTER_CHAIN_DENIED: &str = "denied";

/// Mode of a rule whose match terminates the connection.
pub const SNI_MODE_MITM: &str = "mitm";

/// Transport protocol tls_inspector detects for a ClientHello.
const TRANSPORT_TLS: &str = "tls";

/// Transport protocol Envoy assumes when no inspector detected one.
const TRANSPORT_RAW_BUFFER: &str = "raw_buffer";

/// The rules that decide a connection's TLS at its ClientHello.
#[derive(Debug, Deserialize, PartialEq)]
pub struct EgressPolicy {
  /// Most specific first, as the gateway orders them: a pattern without a
  /// wildcard before one with, then a rule naming its ports before one naming
  /// all of them. The first pattern that matches the SNI decides.
  pub rules: Vec<SniRule>,
}

/// One pattern and what the connection becomes when it is the first to match.
#[derive(Debug, Deserialize, PartialEq)]
pub struct SniRule {
  pub pattern: String,
  pub mode: String,
}

/// Reports whether `hostname`, lowercase and without a trailing dot, matches
/// `pattern` in the policy's grammar: "*" matches every name, "*.suffix"
/// exactly one non-empty leftmost label, and anything else the whole name.
/// The same rules as HostnamePattern.Matches in internal/egresspolicy, which
/// decides the requests inside the connection.
pub fn pattern_matches(pattern: &str, hostname: &str) -> bool {
  if hostname.is_empty() {
    return false;
  }
  if pattern == "*" {
    return true;
  }
  if let Some(suffix) = pattern.strip_prefix("*.") {
    return match hostname
      .strip_suffix(suffix)
      .and_then(|rest| rest.strip_suffix('.'))
    {
      Some(label) => !label.is_empty() && !label.contains('.'),
      None => false,
    };
  }
  pattern == hostname
}

/// Puts an SNI in the form patterns are written in: ASCII lowercase, one
/// trailing dot removed. Only ASCII is folded, as the gateway does, so a
/// non-ASCII spelling cannot match a pattern for a different name.
fn normalize_sni(sni: &str) -> String {
  let lower = sni.to_ascii_lowercase();
  match lower.strip_suffix('.') {
    Some(stripped) => stripped.to_owned(),
    None => lower,
  }
}

/// What the transport protocol alone says about a connection. TLS is decided
/// on its SNI, so nothing yet. No detected transport, or raw_buffer, is
/// cleartext for the HTTP chain to police request by request. Anything else
/// is a transport nothing here knows, and is closed.
pub fn transport_verdict(transport: Option<&str>) -> Option<&'static str> {
  match transport {
    Some(TRANSPORT_TLS) => None,
    None | Some(TRANSPORT_RAW_BUFFER) => Some(ATE_EGRESS_FILTER_CHAIN_CLEARTEXT),
    Some(_) => Some(ATE_EGRESS_FILTER_CHAIN_DENIED),
  }
}

/// Decides a TLS connection: the mode of the first rule matching its SNI.
/// Denied when there is no SNI, no policy, no match, or a mode this filter
/// does not know.
pub fn tls_verdict(policy: Option<&EgressPolicy>, sni: Option<&str>) -> &'static str {
  let (Some(policy), Some(sni)) = (policy, sni) else {
    return ATE_EGRESS_FILTER_CHAIN_DENIED;
  };
  let hostname = normalize_sni(sni);
  match policy
    .rules
    .iter()
    .find(|rule| pattern_matches(&rule.pattern, &hostname))
  {
    Some(rule) if rule.mode == SNI_MODE_MITM => ATE_EGRESS_FILTER_CHAIN_MITM,
    _ => ATE_EGRESS_FILTER_CHAIN_DENIED,
  }
}

/// The filter takes no configuration.
pub struct EgressPolicyFilterConfig;

impl<ELF: EnvoyListenerFilter> ListenerFilterConfig<ELF> for EgressPolicyFilterConfig {
  fn new_listener_filter(&self, _envoy: &mut ELF) -> Box<dyn ListenerFilter<ELF>> {
    Box::new(EgressPolicyFilter)
  }
}

/// Runs after tls_inspector and http_inspector, once per connection.
pub struct EgressPolicyFilter;

impl<ELF: EnvoyListenerFilter> ListenerFilter<ELF> for EgressPolicyFilter {
  fn on_accept(
    &mut self,
    envoy_filter: &mut ELF,
  ) -> envoy_dynamic_module_type_on_listener_filter_status {
    let transport = envoy_filter
      .get_detected_transport_protocol()
      .map(|value| String::from_utf8_lossy(value.as_slice()).into_owned());

    let verdict = match transport_verdict(transport.as_deref()) {
      Some(verdict) => verdict,
      None => {
        let sni = envoy_filter
          .get_requested_server_name()
          .map(|value| String::from_utf8_lossy(value.as_slice()).into_owned());
        // Unparseable rules deny, like absent ones: nothing is allowed by
        // guesswork.
        let policy = envoy_filter
          .get_filter_state_bytes(ATE_POLICY_EGRESS)
          .and_then(|value| serde_json::from_slice::<EgressPolicy>(value.as_slice()).ok());
        let verdict = tls_verdict(policy.as_ref(), sni.as_deref());
        envoy_log_trace!("egress policy: sni={:?} chain={}", sni, verdict);
        verdict
      }
    };

    envoy_filter.set_filter_state_bytes(ATE_EGRESS_FILTER_CHAIN, verdict.as_bytes());
    envoy_log_trace!(
      "egress policy: transport={:?} chain={}",
      transport,
      verdict
    );
    envoy_dynamic_module_type_on_listener_filter_status::Continue
  }
}

declare_listener_filter_init_functions!(init, new_listener_filter_config_fn);

/// Called when the dynamic module is loaded into Envoy.
fn init() -> bool {
  true
}

/// Called when a new listener filter configuration is created.
fn new_listener_filter_config_fn<
  EC: EnvoyListenerFilterConfig,
  ELF: EnvoyListenerFilter,
>(
  _envoy_filter_config: &mut EC,
  _name: &str,
  _config: &[u8],
) -> Option<Box<dyn ListenerFilterConfig<ELF>>> {
  Some(Box::new(EgressPolicyFilterConfig))
}

#[cfg(test)]
mod tests {
  use super::*;
  use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyBuffer, MockEnvoyListenerFilter, MockEnvoyListenerFilterConfig,
  };

  fn policy(rules: &[(&str, &str)]) -> EgressPolicy {
    EgressPolicy {
      rules: rules
        .iter()
        .map(|(pattern, mode)| SniRule {
          pattern: pattern.to_string(),
          mode: mode.to_string(),
        })
        .collect(),
    }
  }

  #[test]
  fn test_pattern_matches() {
    let cases: &[(&str, &str, bool)] = &[
      // "*" matches every name and only names.
      ("*", "anything.example.com", true),
      ("*", "localhost", true),
      ("*", "", false),
      // "*.suffix" matches exactly one non-empty leftmost label.
      ("*.example.com", "api.example.com", true),
      ("*.example.com", "example.com", false),
      ("*.example.com", "a.b.example.com", false),
      ("*.example.com", ".example.com", false),
      ("*.example.com", "xexample.com", false),
      ("*.example.com", "api.example.co", false),
      ("*.example.com", "api.example.com.evil", false),
      // Anything else matches the whole name.
      ("api.example.com", "api.example.com", true),
      ("api.example.com", "www.api.example.com", false),
      ("api.example.com", "api.example.co", false),
      ("example.com", "api.example.com", false),
      // Normalization is the caller's job.
      ("api.example.com", "API.example.com", false),
      ("api.example.com", "api.example.com.", false),
    ];
    for (pattern, hostname, want) in cases {
      assert_eq!(
        pattern_matches(pattern, hostname),
        *want,
        "pattern_matches({pattern:?}, {hostname:?})"
      );
    }
  }

  #[test]
  fn test_normalize_sni() {
    assert_eq!(normalize_sni("API.Example.COM."), "api.example.com");
    assert_eq!(normalize_sni("api.example.com"), "api.example.com");
    // One trailing dot, not every one.
    assert_eq!(normalize_sni("api.example.com.."), "api.example.com.");
    // Only ASCII folds: U+212A KELVIN SIGN stays itself and cannot become "k".
    assert_eq!(normalize_sni("\u{212A}.example.com"), "\u{212A}.example.com");
  }

  #[test]
  fn test_transport_verdict() {
    assert_eq!(transport_verdict(Some("tls")), None);
    assert_eq!(transport_verdict(None), Some(ATE_EGRESS_FILTER_CHAIN_CLEARTEXT));
    assert_eq!(
      transport_verdict(Some("raw_buffer")),
      Some(ATE_EGRESS_FILTER_CHAIN_CLEARTEXT)
    );
    assert_eq!(transport_verdict(Some("quic")), Some(ATE_EGRESS_FILTER_CHAIN_DENIED));
    assert_eq!(transport_verdict(Some("")), Some(ATE_EGRESS_FILTER_CHAIN_DENIED));
  }

  #[test]
  fn test_tls_verdict_denies_without_inputs() {
    let p = policy(&[("*", SNI_MODE_MITM)]);
    assert_eq!(tls_verdict(None, Some("api.example.com")), ATE_EGRESS_FILTER_CHAIN_DENIED);
    assert_eq!(tls_verdict(Some(&p), None), ATE_EGRESS_FILTER_CHAIN_DENIED);
    assert_eq!(tls_verdict(Some(&p), Some("")), ATE_EGRESS_FILTER_CHAIN_DENIED);
    assert_eq!(
      tls_verdict(Some(&policy(&[])), Some("api.example.com")),
      ATE_EGRESS_FILTER_CHAIN_DENIED
    );
  }

  #[test]
  fn test_tls_verdict_matches_wildcards() {
    let p = policy(&[("api.example.com", SNI_MODE_MITM), ("*.example.org", SNI_MODE_MITM)]);
    assert_eq!(tls_verdict(Some(&p), Some("api.example.com")), ATE_EGRESS_FILTER_CHAIN_MITM);
    assert_eq!(tls_verdict(Some(&p), Some("API.EXAMPLE.COM.")), ATE_EGRESS_FILTER_CHAIN_MITM);
    assert_eq!(tls_verdict(Some(&p), Some("www.example.org")), ATE_EGRESS_FILTER_CHAIN_MITM);
    assert_eq!(tls_verdict(Some(&p), Some("example.org")), ATE_EGRESS_FILTER_CHAIN_DENIED);
    assert_eq!(tls_verdict(Some(&p), Some("a.b.example.org")), ATE_EGRESS_FILTER_CHAIN_DENIED);
    assert_eq!(tls_verdict(Some(&p), Some("www.example.com")), ATE_EGRESS_FILTER_CHAIN_DENIED);

    let any = policy(&[("*", SNI_MODE_MITM)]);
    assert_eq!(tls_verdict(Some(&any), Some("whatever.test")), ATE_EGRESS_FILTER_CHAIN_MITM);
  }

  #[test]
  fn test_tls_verdict_first_match_decides() {
    // The gateway orders the rules most specific first; this filter does not
    // rank them again, so the first match is final even when its mode is one
    // this filter does not know, which denies.
    let unknown_first = policy(&[("*.example.com", "not-a-mode"), ("api.example.com", SNI_MODE_MITM)]);
    assert_eq!(
      tls_verdict(Some(&unknown_first), Some("api.example.com")),
      ATE_EGRESS_FILTER_CHAIN_DENIED
    );
    let known_first = policy(&[("api.example.com", SNI_MODE_MITM), ("*.example.com", "not-a-mode")]);
    assert_eq!(
      tls_verdict(Some(&known_first), Some("api.example.com")),
      ATE_EGRESS_FILTER_CHAIN_MITM
    );
    assert_eq!(
      tls_verdict(Some(&known_first), Some("www.example.com")),
      ATE_EGRESS_FILTER_CHAIN_DENIED
    );
  }

  #[test]
  fn test_policy_json_shape() {
    let parsed: EgressPolicy = serde_json::from_str(
      r#"{"rules":[{"pattern":"api.example.com","mode":"mitm"},{"pattern":"*","mode":"mitm"}]}"#,
    )
    .unwrap();
    assert_eq!(parsed, policy(&[("api.example.com", "mitm"), ("*", "mitm")]));
    assert!(serde_json::from_str::<EgressPolicy>(r#"{"allowed_snis":["api.example.com"]}"#).is_err());
  }

  fn new_filter_config() -> Box<dyn ListenerFilterConfig<MockEnvoyListenerFilter>> {
    let mut mock_config = MockEnvoyListenerFilterConfig::new();
    new_listener_filter_config_fn::<MockEnvoyListenerFilterConfig, MockEnvoyListenerFilter>(
      &mut mock_config,
      "envoy_substrate_egress_policy",
      b"",
    )
    .expect("a filter config")
  }

  /// Runs on_accept for a TLS connection with the given SNI and policy filter
  /// state, asserting the verdict written.
  fn assert_tls_verdict(sni: Option<&'static [u8]>, policy: Option<&'static [u8]>, want: &'static str) {
    let config = new_filter_config();
    let mut mock_filter = MockEnvoyListenerFilter::new();
    mock_filter
      .expect_get_detected_transport_protocol()
      .returning(|| Some(EnvoyBuffer::new(b"tls")));
    mock_filter
      .expect_get_requested_server_name()
      .returning(move || sni.map(EnvoyBuffer::new));
    mock_filter
      .expect_get_filter_state_bytes()
      .withf(|key| key == ATE_POLICY_EGRESS)
      .returning(move |_| policy.map(EnvoyBuffer::new));
    mock_filter
      .expect_set_filter_state_bytes()
      .withf(move |key, value| key == ATE_EGRESS_FILTER_CHAIN && value == want.as_bytes())
      .times(1)
      .returning(|_, _| true);

    let mut filter = config.new_listener_filter(&mut mock_filter);
    assert_eq!(
      filter.on_accept(&mut mock_filter),
      envoy_dynamic_module_type_on_listener_filter_status::Continue
    );
  }

  /// Runs on_accept for a connection with the given detected transport,
  /// asserting the verdict written. Neither the SNI nor the policy is read.
  fn assert_transport_verdict(transport: Option<&'static [u8]>, want: &'static str) {
    let config = new_filter_config();
    let mut mock_filter = MockEnvoyListenerFilter::new();
    mock_filter
      .expect_get_detected_transport_protocol()
      .returning(move || transport.map(EnvoyBuffer::new));
    mock_filter
      .expect_set_filter_state_bytes()
      .withf(move |key, value| key == ATE_EGRESS_FILTER_CHAIN && value == want.as_bytes())
      .times(1)
      .returning(|_, _| true);

    let mut filter = config.new_listener_filter(&mut mock_filter);
    assert_eq!(
      filter.on_accept(&mut mock_filter),
      envoy_dynamic_module_type_on_listener_filter_status::Continue
    );
    assert_eq!(
      filter.on_data(&mut mock_filter, 0),
      envoy_dynamic_module_type_on_listener_filter_status::Continue
    );
  }

  #[test]
  fn test_init() {
    assert!(init());
  }

  #[test]
  fn test_on_accept_no_transport_is_cleartext() {
    assert_transport_verdict(None, ATE_EGRESS_FILTER_CHAIN_CLEARTEXT);
  }

  #[test]
  fn test_on_accept_raw_buffer_is_cleartext() {
    assert_transport_verdict(Some(b"raw_buffer"), ATE_EGRESS_FILTER_CHAIN_CLEARTEXT);
  }

  #[test]
  fn test_on_accept_unknown_transport_is_denied() {
    assert_transport_verdict(Some(b"quic"), ATE_EGRESS_FILTER_CHAIN_DENIED);
  }

  const RULES: &[u8] =
    br#"{"rules":[{"pattern":"api.google.com","mode":"mitm"},{"pattern":"*.google.com","mode":"mitm"}]}"#;

  #[test]
  fn test_on_accept_matching_sni() {
    assert_tls_verdict(Some(b"api.google.com"), Some(RULES), ATE_EGRESS_FILTER_CHAIN_MITM);
  }

  #[test]
  fn test_on_accept_wildcard_sni() {
    assert_tls_verdict(Some(b"mail.google.com"), Some(RULES), ATE_EGRESS_FILTER_CHAIN_MITM);
  }

  #[test]
  fn test_on_accept_case_insensitive_sni() {
    assert_tls_verdict(Some(b"API.Google.COM"), Some(RULES), ATE_EGRESS_FILTER_CHAIN_MITM);
  }

  #[test]
  fn test_on_accept_mismatched_sni() {
    assert_tls_verdict(Some(b"google.com"), Some(RULES), ATE_EGRESS_FILTER_CHAIN_DENIED);
    assert_tls_verdict(Some(b"www.example.com"), Some(RULES), ATE_EGRESS_FILTER_CHAIN_DENIED);
  }

  #[test]
  fn test_on_accept_no_rules() {
    assert_tls_verdict(Some(b"api.google.com"), Some(br#"{"rules":[]}"#), ATE_EGRESS_FILTER_CHAIN_DENIED);
  }

  #[test]
  fn test_on_accept_invalid_policy_json() {
    assert_tls_verdict(Some(b"api.google.com"), Some(b"not-json"), ATE_EGRESS_FILTER_CHAIN_DENIED);
  }

  #[test]
  fn test_on_accept_missing_policy() {
    assert_tls_verdict(Some(b"api.google.com"), None, ATE_EGRESS_FILTER_CHAIN_DENIED);
  }

  #[test]
  fn test_on_accept_missing_sni() {
    assert_tls_verdict(None, Some(RULES), ATE_EGRESS_FILTER_CHAIN_DENIED);
  }
}
