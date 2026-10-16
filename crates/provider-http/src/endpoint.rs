//! Bounded HTTP endpoint validation shared by admission and transport.

use orbit_adapter::error::AdapterError;
use orbit_adapter::types::{EndpointScheme, ProviderRouteBinding};
use reqwest::Url;
use std::collections::BTreeSet;
use std::net::IpAddr;

const MAX_ENDPOINT_BYTES: usize = 2048;
const MAX_QUERY_BYTES: usize = 2048;
const INVALID_QUERY: &str =
    "provider endpoint query must be bounded, unambiguous and credential-free";
const INVALID_ENDPOINT: &str =
    "provider endpoint must be canonical HTTP(S) without credentials or fragments";

/// Validate the original input before URL parsing can discard whitespace.
pub fn validate_provider_url(raw: &str) -> Result<Url, &'static str> {
    if raw.is_empty()
        || raw.len() > MAX_ENDPOINT_BYTES
        || raw
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
    {
        return Err(INVALID_ENDPOINT);
    }
    let (scheme, rest) = raw.split_once("://").ok_or(INVALID_ENDPOINT)?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(INVALID_ENDPOINT);
    }
    let authority = rest.split(['/', '?', '#']).next().ok_or(INVALID_ENDPOINT)?;
    if authority.is_empty() || authority.contains('@') {
        return Err(INVALID_ENDPOINT);
    }
    let url = Url::parse(raw).map_err(|_| INVALID_ENDPOINT)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() == Some(0)
        || (url.scheme() == "http" && !loopback_host(url.host_str().unwrap_or("")))
    {
        return Err(INVALID_ENDPOINT);
    }
    validate_endpoint_query(url.query())?;
    Ok(url)
}

/// Keep valid raw query bytes unchanged. Validation never exposes input bytes.
pub fn validate_endpoint_query(query: Option<&str>) -> Result<(), &'static str> {
    let Some(raw) = query else {
        return Ok(());
    };
    if raw.is_empty()
        || raw.len() > MAX_QUERY_BYTES
        || raw.starts_with('?')
        || raw.split('&').any(str::is_empty)
        || raw
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '#' | '\\'))
    {
        return Err(INVALID_QUERY);
    }
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err(INVALID_QUERY);
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    let mut parsed = Url::parse("https://query.invalid/").map_err(|_| INVALID_QUERY)?;
    parsed.set_query(Some(raw));
    if parsed.query() != Some(raw) || parsed.fragment().is_some() {
        return Err(INVALID_QUERY);
    }
    let mut seen = BTreeSet::new();
    for (key, _) in parsed.query_pairs() {
        if key.is_empty()
            || key
                .chars()
                .any(|c| c.is_control() || c.is_whitespace() || c == '\u{fffd}')
            || !seen.insert(key.clone().into_owned())
        {
            return Err(INVALID_QUERY);
        }
        let normalized: String = key
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_lowercase())
            .collect();
        if [
            "apikey",
            "xapikey",
            "key",
            "token",
            "accesstoken",
            "refreshtoken",
            "sessiontoken",
            "idtoken",
            "bearertoken",
            "password",
            "secret",
            "clientsecret",
            "authorization",
            "auth",
            "credential",
            "credentials",
            "sig",
            "signature",
            "sharedaccesssignature",
            "xamzcredential",
            "xamzsignature",
            "xamzsecuritytoken",
            "xgoogcredential",
            "xgoogsignature",
        ]
        .contains(&normalized.as_str())
        {
            return Err(INVALID_QUERY);
        }
    }
    Ok(())
}

fn loopback_host(host: &str) -> bool {
    host == "localhost"
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Construct the complete path before attaching the exact separately bound query.
/// The default is supplied by the concrete adapter, never inferred from its kind.
pub fn provider_method_url(
    route: &ProviderRouteBinding,
    default_base: &str,
    method: &str,
) -> Result<String, AdapterError> {
    let invalid = || AdapterError::ProviderConfigurationInvalid(INVALID_ENDPOINT.into());
    validate_endpoint_query(route.endpoint_query.as_deref())
        .map_err(|message| AdapterError::ProviderConfigurationInvalid(message.into()))?;
    let scheme = match route.endpoint_scheme {
        EndpointScheme::Https => "https",
        EndpointScheme::HttpLoopback => "http",
        EndpointScheme::LocalProcess => return Err(invalid()),
    };
    let host = &route.endpoint_host;
    if host.is_empty()
        || host.len() > 255
        || route.endpoint_port == 0
        || host.chars().any(|c| {
            c.is_control() || c.is_whitespace() || matches!(c, '@' | '/' | '?' | '#' | '\\' | '%')
        })
    {
        return Err(invalid());
    }
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    let host = match unbracketed.parse::<IpAddr>() {
        Ok(IpAddr::V6(address)) => format!("[{address}]"),
        Ok(IpAddr::V4(address)) if unbracketed == host.as_str() => address.to_string(),
        _ if host.chars().any(|c| matches!(c, ':' | '[' | ']')) => return Err(invalid()),
        _ => host.clone(),
    };
    let mut url = Url::parse(&format!("{scheme}://endpoint.invalid/")).map_err(|_| invalid())?;
    url.set_host(Some(&host)).map_err(|_| invalid())?;
    url.set_port(Some(route.endpoint_port))
        .map_err(|_| invalid())?;
    let canonical_host = url.host_str().ok_or_else(invalid)?.to_owned();
    if scheme == "http" && !loopback_host(&canonical_host) {
        return Err(invalid());
    }
    let base = if route.endpoint_path.is_empty() {
        default_base
    } else {
        &route.endpoint_path
    };
    if base.len() > MAX_ENDPOINT_BYTES
        || !base.starts_with('/')
        || base.ends_with('/')
        || !matches!(method, "chat/completions" | "messages" | "chat")
    {
        return Err(invalid());
    }
    let path = format!("{base}/{method}");
    url.set_path(&path);
    url.set_query(route.endpoint_query.as_deref());
    if url.path() != path
        || url.query() != route.endpoint_query.as_deref()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.scheme() != scheme
        || url.host_str() != Some(canonical_host.as_str())
        || url.port_or_known_default() != Some(route.endpoint_port)
    {
        return Err(invalid());
    }
    // Retain explicit default ports in the existing public URL helper output.
    let mut wire = format!("{scheme}://{canonical_host}:{}{path}", route.endpoint_port);
    if let Some(query) = &route.endpoint_query {
        wire.push('?');
        wire.push_str(query);
    }
    let final_url = Url::parse(&wire).map_err(|_| invalid())?;
    if final_url.scheme() != scheme
        || final_url.host_str() != Some(canonical_host.as_str())
        || final_url.port_or_known_default() != Some(route.endpoint_port)
        || !final_url.username().is_empty()
        || final_url.password().is_some()
        || final_url.path() != path
        || final_url.query() != route.endpoint_query.as_deref()
        || final_url.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(wire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orbit_adapter::types::*;

    fn route(host: &str, port: u16, path: &str, query: Option<&str>) -> ProviderRouteBinding {
        let identity = crate::openai::openai_identity();
        ProviderRouteBinding {
            provider_id: ProviderId("endpoint-fixture".into()),
            deployment_id: DeploymentId("endpoint-fixture".into()),
            region_id: RegionId("endpoint-fixture".into()),
            adapter_kind: identity.kind,
            adapter_implementation_digest: identity.implementation_digest,
            adapter_profile_digest: identity.profile_digest,
            endpoint_digest: Sha256Digest("e".repeat(64)),
            expected_model: "raw-model".into(),
            pricing_digest: Sha256Digest("p".repeat(64)),
            endpoint_host: host.into(),
            endpoint_port: port,
            endpoint_scheme: EndpointScheme::HttpLoopback,
            endpoint_path: path.into(),
            endpoint_query: query.map(str::to_owned),
        }
    }

    #[test]
    fn query_raw_escaping_and_method_order_are_exact() {
        let query = "scope=synthetic&escaped=a%2Fb%26c%3Dd%2Be&space=a+b";
        let route = route("127.0.0.1", 8123, "/proxy/v1", Some(query));
        for method in ["chat/completions", "messages", "chat"] {
            let wire = provider_method_url(&route, "/v1", method).unwrap();
            assert_eq!(
                wire,
                format!("http://127.0.0.1:8123/proxy/v1/{method}?{query}")
            );
            let parsed = Url::parse(&wire).unwrap();
            assert_eq!(parsed.query(), Some(query));
            assert_eq!(parsed.host_str(), Some("127.0.0.1"));
            assert_eq!(parsed.port_or_known_default(), Some(8123));
        }
    }

    #[test]
    fn ipv6_bare_and_bracketed_hosts_have_one_correct_authority() {
        for host in ["::1", "[::1]"] {
            let mut route = route(host, 8123, "/api", Some("scope=synthetic"));
            let wire = provider_method_url(&route, "/api", "chat").unwrap();
            assert_eq!(wire, "http://[::1]:8123/api/chat?scope=synthetic");
            let parsed = Url::parse(&wire).unwrap();
            assert_eq!(parsed.host_str(), Some("[::1]"));
            assert_eq!(parsed.port_or_known_default(), Some(8123));
            assert!(parsed.username().is_empty() && parsed.password().is_none());
            route.endpoint_scheme = EndpointScheme::Https;
            route.endpoint_port = 443;
            let wire = provider_method_url(&route, "/api", "chat").unwrap();
            assert_eq!(wire, "https://[::1]:443/api/chat?scope=synthetic");
            assert_eq!(
                Url::parse(&wire).unwrap().port_or_known_default(),
                Some(443)
            );
        }
    }

    #[test]
    fn canonical_dns_and_explicit_default_port_are_retained() {
        let mut route = route("EXAMPLE.COM", 443, "", None);
        route.endpoint_scheme = EndpointScheme::Https;
        assert_eq!(
            provider_method_url(&route, "/v1", "messages").unwrap(),
            "https://example.com:443/v1/messages"
        );
    }

    #[test]
    fn hostile_authorities_are_refused_without_echo() {
        for host in [
            "user@127.0.0.1",
            "127.0.0.1:8123/path",
            "127.0.0.1?scope=one",
            "127.0.0.1#fragment",
            "127.0.0.1\\path",
            "127.0.0.1\n",
            "127.0.0.1\t",
            "[::1]:8123",
            "[::1",
            "::1]",
            "%31%32%37.0.0.1",
        ] {
            let route = route(host, 8123, "/v1", None);
            let error = provider_method_url(&route, "/v1", "messages").unwrap_err();
            assert_eq!(error.code(), "E0401");
            assert!(!error.to_string().contains(host));
        }
    }

    #[test]
    fn http_loopback_and_local_process_transport_are_enforced() {
        for host in ["example.com", "192.0.2.1", "[2001:db8::1]"] {
            assert!(
                provider_method_url(&route(host, 8123, "/v1", None), "/v1", "messages").is_err()
            );
        }
        for host in ["localhost", "127.0.0.1", "::1"] {
            assert!(
                provider_method_url(&route(host, 8123, "/v1", None), "/v1", "messages").is_ok()
            );
        }
        let mut local = route("localhost", 8123, "/v1", None);
        local.endpoint_scheme = EndpointScheme::LocalProcess;
        assert!(provider_method_url(&local, "/v1", "messages").is_err());
        local.endpoint_scheme = EndpointScheme::HttpLoopback;
        local.endpoint_port = 0;
        assert!(provider_method_url(&local, "/v1", "messages").is_err());
    }

    #[test]
    fn noncanonical_path_cannot_change_the_authority_or_query() {
        for path in [
            "v1",
            "/v1/",
            "/v1/../outside",
            "/v1/%2e%2e/outside",
            "/v1?scope=other",
            "/v1#fragment",
            "/v1\\outside",
            "/v1\n",
            "/v1 ",
        ] {
            assert!(
                provider_method_url(
                    &route("127.0.0.1", 8123, path, Some("scope=one")),
                    "/v1",
                    "messages"
                )
                .is_err()
            );
        }
    }

    #[test]
    fn raw_url_controls_whitespace_and_backslash_are_rejected_before_parse() {
        for raw in [
            "http://127.0.0.1/v1?scope=syn\nthetic",
            "http://127.0.0.1/v1?scope=syn\tthetic",
            " http://127.0.0.1/v1",
            "http://127.0.0.1/v1 ",
            "http://127.0.0.1/tenant\\v1",
            "http://127.0.0.1/v1?scope=has space",
        ] {
            assert!(validate_provider_url(raw).is_err());
        }
    }

    #[test]
    fn raw_url_explicit_zero_port_is_refused_before_dispatch() {
        assert!(validate_provider_url("http://127.0.0.1:0/v1?scope=synthetic").is_err());
        assert!(validate_provider_url("https://example.com:0/v1?scope=synthetic").is_err());
    }

    #[test]
    fn raw_url_userinfo_fragment_non_http_and_remote_http_are_rejected() {
        for raw in [
            "http://user:pass@127.0.0.1/v1",
            "http://@127.0.0.1/v1",
            "https://@example.com/v1",
            "https:example.com/v1",
            "http://127.0.0.1/v1#fragment",
            "file:///v1",
            "http://example.com/v1",
        ] {
            assert!(validate_provider_url(raw).is_err());
        }
        assert!(validate_provider_url("https://example.com/v1?scope=a%2Fb").is_ok());
        assert!(validate_provider_url("https://example.com/v1?scope=a%40b%3Ac").is_ok());
        assert!(validate_provider_url("https://example.com/v1?scope=a@b").is_ok());
        assert!(validate_provider_url("http://[::1]:8123/api?scope=one").is_ok());
    }

    #[test]
    fn duplicate_decoded_empty_and_malformed_query_keys_are_rejected() {
        for query in [
            "",
            "?scope=one",
            "scope=one#fragment",
            "scope=one\n",
            "scope=one\\two",
            "scope=%GG",
            "scope=%1",
            "scope=%",
            "scope=one&scope=two",
            "scope=one&%73cope=two",
            "=one",
            "scope=one&&other=two",
            "scope=one&",
            "%00=one",
            "%FF=one",
        ] {
            assert!(validate_endpoint_query(Some(query)).is_err());
        }
    }

    #[test]
    fn credential_and_signed_query_names_are_rejected_after_decoding() {
        for key in [
            "api_key",
            "%61pi_key",
            "X-Api-Key",
            "access_token",
            "client_secret",
            "authorization",
            "credentials",
            "sig",
            "signature",
            "X-Amz-Credential",
            "X-Amz-Signature",
            "X-Amz-Security-Token",
            "X-Goog-Signature",
        ] {
            let query = format!("{key}=synthetic-secret");
            let error = validate_endpoint_query(Some(&query)).unwrap_err();
            assert!(!error.contains("synthetic-secret") && !error.contains(key));
        }
    }

    #[test]
    fn query_and_raw_url_size_bounds_are_exact() {
        let query = format!("scope={}", "a".repeat(MAX_QUERY_BYTES - 6));
        assert!(validate_endpoint_query(Some(&query)).is_ok());
        assert!(validate_endpoint_query(Some(&(query + "a"))).is_err());
        let prefix = "https://example.com/";
        let raw = format!("{prefix}{}", "a".repeat(MAX_ENDPOINT_BYTES - prefix.len()));
        assert!(validate_provider_url(&raw).is_ok());
        assert!(validate_provider_url(&(raw + "a")).is_err());
    }

    #[test]
    fn concrete_ollama_requires_explicit_api_base_and_http_loopback() {
        use crate::AsyncProviderAdapter;
        let mut route = route("127.0.0.1", 8123, "/api", None);
        route.adapter_kind = AdapterKind::LocalProcessV1;
        let adapter = crate::OllamaHttpV1::new(
            AdapterIdentity {
                kind: route.adapter_kind,
                implementation_digest: route.adapter_implementation_digest.clone(),
                profile_digest: route.adapter_profile_digest.clone(),
            },
            crate::openai::openai_capabilities(),
        )
        .unwrap();
        assert!(adapter.validate_route(&route).is_ok());
        route.endpoint_path = "/proxy/api".into();
        assert!(adapter.validate_route(&route).is_ok());
        for path in ["", "/proxy", "/api/", "/proxy/api/../api"] {
            route.endpoint_path = path.into();
            assert!(adapter.validate_route(&route).is_err());
        }
        route.endpoint_path = "/api".into();
        route.endpoint_scheme = EndpointScheme::Https;
        assert!(adapter.validate_route(&route).is_err());
        route.endpoint_scheme = EndpointScheme::LocalProcess;
        assert!(adapter.validate_route(&route).is_err());
    }
}
