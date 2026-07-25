use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use azure_core::error::ResultExt;
use azure_core::http::{AsyncRawResponse, Sanitizer};
use futures_util::TryStreamExt;
use http_body_util::BodyExt;
use tracing::{debug, error, warn};
use typespec_client_core::http::DEFAULT_ALLOWED_QUERY_PARAMETERS;

use crate::http::backendtls::SYSTEM_TRUST;
use crate::http::filters::BackendRequestTimeout;
use crate::proxy::httpproxy::PolicyClient;
use crate::types::agent::{BackendTrafficPolicy, SimpleBackendReference, Target};

/// Default credential-flow timeout, overridable by a backend request-timeout policy
pub(super) const DEFAULT_CREDENTIAL_FLOW_TIMEOUT: Duration = Duration::from_secs(5);

/// Total budget for a token fetch. Bounds the parts a per-request timeout cannot:
/// the implicit chain's sequential attempts, and `DeveloperToolsCredential`
/// shelling out to the Azure CLI. Never below the per-request timeout, so a
/// configured `requestTimeout` is reachable.
pub(super) fn credential_flow_budget(policies: &[BackendTrafficPolicy]) -> Duration {
	policies
		.iter()
		.find_map(|p| match p {
			BackendTrafficPolicy::HTTP(h) => h.request_timeout,
			_ => None,
		})
		.map_or(DEFAULT_CREDENTIAL_FLOW_TIMEOUT, |t| {
			t.max(DEFAULT_CREDENTIAL_FLOW_TIMEOUT)
		})
}

/// HTTP transport for the Azure SDK that routes credential-flow requests (Microsoft
/// Entra ID, IMDS, etc.) through the gateway's policy-aware client, so connection
/// policies such as `backendTunnel` and `backendTLS` apply to token fetches like any
/// other outbound call. The token endpoints are chosen dynamically by the SDK, so
/// each request targets an inline backend derived from the request URL.
#[derive(Debug)]
pub(super) struct AzurePolicyHttpClient {
	pub client: PolicyClient,
	pub policies: Arc<Vec<BackendTrafficPolicy>>,
}

impl AzurePolicyHttpClient {
	/// The policies to apply for a given endpoint. TLS is scheme dependent: the
	/// implicit credential chain mixes HTTPS (Entra ID) and plaintext HTTP (IMDS)
	/// endpoints, so TLS must only apply to the former. Similarly, tunnels are
	/// never applied to host-local endpoints (IMDS, Arc/Cloud Shell identity
	/// endpoints on localhost): they are only reachable from the host itself, so
	/// a proxy can never dial them, and Azure requires metadata requests to
	/// bypass proxies (IMDS rejects forwarded requests).
	fn policies_for_endpoint(&self, scheme: &str, target: &Target) -> Vec<BackendTrafficPolicy> {
		let mut policies: Vec<BackendTrafficPolicy> = self.policies.as_ref().clone();
		if scheme == "https" {
			if !policies
				.iter()
				.any(|p| matches!(p, BackendTrafficPolicy::BackendTLS(_)))
			{
				policies.push(BackendTrafficPolicy::BackendTLS(SYSTEM_TRUST.clone()));
			}
		} else {
			policies.retain(|p| !matches!(p, BackendTrafficPolicy::BackendTLS(_)));
		}
		if is_host_local(target) {
			policies.retain(|p| !matches!(p, BackendTrafficPolicy::Tunnel(_)));
		}
		policies
	}
}

/// Returns true for destinations only reachable from this host: link-local
/// addresses such as the IMDS endpoint (169.254.169.254), and loopback
/// endpoints used by the managed-identity sources on Azure Arc, Cloud Shell,
/// and Service Fabric (e.g. `http://localhost:40342`, via IDENTITY_ENDPOINT).
/// A forward proxy would dial its own link-local/loopback space, not ours.
/// The SDK addresses IMDS by IP literal and the loopback endpoints as
/// `localhost`, so these checks are sufficient.
fn is_host_local(target: &Target) -> bool {
	match target {
		Target::Address(addr) => match addr.ip() {
			std::net::IpAddr::V4(ip) => ip.is_link_local() || ip.is_loopback(),
			std::net::IpAddr::V6(ip) => ip.is_unicast_link_local() || ip.is_loopback(),
		},
		Target::Hostname(host, _) => host.eq_ignore_ascii_case("localhost"),
		_ => false,
	}
}

#[async_trait]
impl azure_core::http::HttpClient for AzurePolicyHttpClient {
	async fn execute_request(
		&self,
		request: &azure_core::http::Request,
	) -> azure_core::Result<AsyncRawResponse> {
		let url = request.url().clone();
		let method = request.method();
		let mut req = ::http::Request::builder();
		req = req.method(from_method(method)?).uri(url.as_str());
		for (name, value) in request.headers().iter() {
			req = req.header(name.as_str(), value.as_str());
		}
		let body = request.body().clone();

		let mut request = match body {
			azure_core::http::Body::Bytes(bytes) => req.body(crate::http::Body::from(bytes)),

			// We cannot currently implement `Body::SeekableStream` for WASM
			// because `reqwest::Body::wrap_stream()` is not implemented for WASM.
			#[cfg(not(target_arch = "wasm32"))]
			azure_core::http::Body::SeekableStream(seekable_stream) => {
				req.body(crate::http::Body::from_stream(seekable_stream))
			},
		}
		.map_err(|e| {
			azure_core::Error::with_error(
				azure_core::error::ErrorKind::Other,
				e,
				"failed to build `agentgateway` policy client request",
			)
		})?;

		// Default timeout, overridable by backend request-timeout policy
		request
			.extensions_mut()
			.insert(BackendRequestTimeout(DEFAULT_CREDENTIAL_FLOW_TIMEOUT));

		let Some(host) = url.host() else {
			return Err(azure_core::Error::with_message(
				azure_core::error::ErrorKind::DataConversion,
				format!(
					"credential request url '{}' has no host",
					url.sanitize(&DEFAULT_ALLOWED_QUERY_PARAMETERS)
				),
			));
		};
		let target = match host {
			url::Host::Domain(h) => Target::from((h, url.port_or_known_default().unwrap_or(80))),
			url::Host::Ipv4(ip) => Target::Address(SocketAddr::from((
				ip,
				url.port_or_known_default().unwrap_or(80),
			))),
			url::Host::Ipv6(ip) => Target::Address(SocketAddr::from((
				ip,
				url.port_or_known_default().unwrap_or(80),
			))),
		};
		let policies = self.policies_for_endpoint(url.scheme(), &target);

		debug!(
			"performing request {method} '{}' with `agentgateway` policy client",
			url.sanitize(&DEFAULT_ALLOWED_QUERY_PARAMETERS)
		);
		let rsp = self
			.client
			.call_reference_with_policies(
				request,
				&SimpleBackendReference::InlineBackend(target),
				&policies,
			)
			.await
			.map_err(|e| {
				error!("request failed: {e}");
				azure_core::Error::with_error(
					azure_core::error::ErrorKind::Io,
					e,
					"failed to execute `agentgateway` policy client request",
				)
			})?;

		let status = rsp.status();
		let headers = to_headers(rsp.headers());

		let body: azure_core::http::response::PinnedStream =
			Box::pin(rsp.into_data_stream().map_err(|error| {
				azure_core::Error::with_error(
					azure_core::error::ErrorKind::Io,
					error,
					"error converting response into a byte stream",
				)
			}));

		Ok(AsyncRawResponse::new(status.as_u16().into(), headers, body))
	}
}

fn from_method(method: azure_core::http::Method) -> azure_core::Result<http::Method> {
	match method {
		azure_core::http::Method::Get => Ok(http::Method::GET),
		azure_core::http::Method::Head => Ok(http::Method::HEAD),
		azure_core::http::Method::Post => Ok(http::Method::POST),
		azure_core::http::Method::Put => Ok(http::Method::PUT),
		azure_core::http::Method::Delete => Ok(http::Method::DELETE),
		azure_core::http::Method::Patch => Ok(http::Method::PATCH),
		_ => http::Method::from_str(method.as_str())
			.with_kind(azure_core::error::ErrorKind::DataConversion),
	}
}

fn to_headers(map: &::http::HeaderMap) -> azure_core::http::headers::Headers {
	let map = map
		.iter()
		.filter_map(|(k, v)| {
			let key = k.as_str();
			if let Ok(value) = v.to_str() {
				Some((
					azure_core::http::headers::HeaderName::from(key.to_owned()),
					azure_core::http::headers::HeaderValue::from(value.to_owned()),
				))
			} else {
				warn!("header value for `{key}` is not utf8");
				None
			}
		})
		.collect::<HashMap<_, _>>();
	azure_core::http::headers::Headers::from(map)
}

#[cfg(test)]
mod tests {
	use azure_core::http::HttpClient;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::net::{TcpListener, TcpStream};
	use tokio::sync::oneshot;

	use super::*;
	use crate::test_helpers::proxymock::{setup_proxy_test, simple_mock};
	use crate::types::backend::Tunnel;

	fn tunnel_policy(proxy: std::net::SocketAddr) -> BackendTrafficPolicy {
		BackendTrafficPolicy::Tunnel(Tunnel {
			proxy: Arc::new(SimpleBackendReference::InlineBackend(Target::Address(
				proxy,
			))),
		})
	}

	fn adapter(policies: Vec<BackendTrafficPolicy>) -> AzurePolicyHttpClient {
		AzurePolicyHttpClient {
			client: PolicyClient::new(setup_proxy_test("{}").expect("setup proxy inputs").inputs()),
			policies: Arc::new(policies),
		}
	}

	fn entra_target() -> Target {
		Target::from(("login.microsoftonline.com", 443))
	}

	fn imds_target() -> Target {
		Target::Address("169.254.169.254:80".parse().unwrap())
	}

	#[tokio::test]
	async fn policies_for_endpoint_https_appends_system_trust() {
		let proxy = "127.0.0.1:3128".parse().unwrap();
		let client = adapter(vec![tunnel_policy(proxy)]);
		let policies = client.policies_for_endpoint("https", &entra_target());
		assert!(matches!(policies[0], BackendTrafficPolicy::Tunnel(_)));
		assert!(matches!(policies[1], BackendTrafficPolicy::BackendTLS(_)));
		assert_eq!(policies.len(), 2);
	}

	#[tokio::test]
	async fn policies_for_endpoint_https_keeps_configured_tls() {
		let client = adapter(vec![BackendTrafficPolicy::BackendTLS(
			crate::http::backendtls::INSECURE_TRUST.clone(),
		)]);
		let policies = client.policies_for_endpoint("https", &entra_target());
		let [BackendTrafficPolicy::BackendTLS(tls)] = policies.as_slice() else {
			panic!("expected only the configured TLS policy, got {policies:?}");
		};
		assert!(tls.metadata.insecure);
	}

	#[tokio::test]
	async fn policies_for_endpoint_http_strips_tls() {
		let proxy = "127.0.0.1:3128".parse().unwrap();
		let client = adapter(vec![
			tunnel_policy(proxy),
			BackendTrafficPolicy::BackendTLS(SYSTEM_TRUST.clone()),
		]);
		// Remote plaintext target: tunnel must survive; TLS must be stripped.
		let target = Target::from(("token.internal", 8080));
		let policies = client.policies_for_endpoint("http", &target);
		assert!(
			matches!(policies.as_slice(), [BackendTrafficPolicy::Tunnel(_)]),
			"plaintext endpoints must not get TLS: {policies:?}"
		);
	}

	#[tokio::test]
	async fn policies_for_endpoint_host_local_strips_tunnel() {
		let proxy = "127.0.0.1:3128".parse().unwrap();
		let client = adapter(vec![tunnel_policy(proxy)]);
		// Host-local endpoints are only reachable from the host itself, never via
		// a proxy, so the tunnel must not apply: IMDS (link-local) and the
		// Arc/Cloud Shell identity endpoints (localhost / loopback).
		for target in [
			imds_target(),
			Target::Address("127.0.0.1:40342".parse().unwrap()),
			Target::Address("[::1]:40342".parse().unwrap()),
			Target::from(("localhost", 40342)),
		] {
			let policies = client.policies_for_endpoint("http", &target);
			assert!(
				policies.is_empty(),
				"host-local endpoint {target:?} must bypass the tunnel: {policies:?}"
			);
		}
		// ...but the Entra ID leg of the same credential chain keeps the tunnel.
		let policies = client.policies_for_endpoint("https", &entra_target());
		assert!(matches!(policies[0], BackendTrafficPolicy::Tunnel(_)));
	}

	fn http_timeout_policy(timeout: Duration) -> BackendTrafficPolicy {
		BackendTrafficPolicy::HTTP(crate::types::backend::HTTP {
			request_timeout: Some(timeout),
			..Default::default()
		})
	}

	#[test]
	fn credential_flow_budget_defaults() {
		let proxy = "127.0.0.1:3128".parse().unwrap();
		assert_eq!(
			credential_flow_budget(&[tunnel_policy(proxy)]),
			DEFAULT_CREDENTIAL_FLOW_TIMEOUT
		);
	}

	#[test]
	fn credential_flow_budget_honors_larger_override() {
		let configured = Duration::from_secs(30);
		assert_eq!(
			credential_flow_budget(&[http_timeout_policy(configured)]),
			configured,
			"a raised requestTimeout must not be capped by the total budget"
		);
	}

	#[test]
	fn credential_flow_budget_clamps_smaller_override() {
		// A short per-request timeout still leaves the implicit chain room to try
		// several sources.
		assert_eq!(
			credential_flow_budget(&[http_timeout_policy(Duration::from_secs(1))]),
			DEFAULT_CREDENTIAL_FLOW_TIMEOUT
		);
	}

	/// Mock forward proxy: captures the request head it receives, then pipes the
	/// connection to `upstream`. For CONNECT it completes the handshake first.
	fn spawn_mock_proxy(
		listener: TcpListener,
		upstream: std::net::SocketAddr,
	) -> oneshot::Receiver<String> {
		let (head_tx, head_rx) = oneshot::channel();
		tokio::spawn(async move {
			let (mut downstream, _) = listener.accept().await.unwrap();
			let mut buf = Vec::new();
			loop {
				let mut chunk = [0; 1024];
				let n = downstream.read(&mut chunk).await.unwrap();
				assert!(n > 0, "proxy request unexpectedly closed");
				buf.extend_from_slice(&chunk[..n]);
				if buf.windows(4).any(|w| w == b"\r\n\r\n") {
					break;
				}
			}
			let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
			let head = String::from_utf8(buf[..header_end].to_vec()).unwrap();
			let is_connect = head.starts_with("CONNECT ");
			head_tx.send(head).unwrap();

			let mut upstream = TcpStream::connect(upstream).await.unwrap();
			if is_connect {
				downstream
					.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
					.await
					.unwrap();
			} else {
				// Absolute-form HTTP: replay the buffered request to the upstream.
				upstream.write_all(&buf).await.unwrap();
			}
			tokio::io::copy_bidirectional(&mut downstream, &mut upstream)
				.await
				.ok();
		});
		head_rx
	}

	#[tokio::test]
	async fn execute_request_plaintext_via_tunnel_uses_absolute_form() {
		let origin = simple_mock().await;
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let proxy_addr = listener.local_addr().unwrap();
		let head_rx = spawn_mock_proxy(listener, *origin.address());

		let client = adapter(vec![tunnel_policy(proxy_addr)]);
		// Use a hostname target: loopback targets are host-local and would
		// (correctly) bypass the tunnel. The name is never resolved — tunneled
		// requests are dialed via the proxy, which pipes to the mock origin.
		let url = format!("http://token.test:{}/token", origin.address().port());
		let request =
			azure_core::http::Request::new(url.parse().unwrap(), azure_core::http::Method::Get);
		let rsp = client.execute_request(&request).await.unwrap();
		assert_eq!(u16::from(rsp.status()), 200);
		// simple_mock echoes the request; a non-empty body proves the round trip
		let body = rsp.into_body().collect_string().await.unwrap();
		assert!(!body.is_empty());

		let head = head_rx.await.unwrap();
		assert!(
			head.starts_with(&format!("GET {url} HTTP/1.1\r\n")),
			"expected absolute-form request via proxy, got: {head}"
		);
	}

	#[cfg(feature = "tls-aws-lc")]
	#[tokio::test]
	async fn execute_request_https_via_tunnel_uses_connect() {
		let (origin, _certs) = crate::test_helpers::proxymock::tls_mock().await;
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let proxy_addr = listener.local_addr().unwrap();
		let head_rx = spawn_mock_proxy(listener, *origin.address());

		// The mock TLS server uses a self-signed cert, so provide an explicit
		// (insecure) backendTLS policy; this also exercises the "user TLS policy
		// wins over the SYSTEM_TRUST default" path.
		let client = adapter(vec![
			tunnel_policy(proxy_addr),
			BackendTrafficPolicy::BackendTLS(crate::http::backendtls::INSECURE_TRUST.clone()),
		]);
		// Hostname target, as loopback would (correctly) bypass the tunnel; the
		// proxy pipes to the mock origin without resolving the name.
		let url = format!("https://token.test:{}/token", origin.address().port());
		let request =
			azure_core::http::Request::new(url.parse().unwrap(), azure_core::http::Method::Get);
		let rsp = client.execute_request(&request).await.unwrap();
		assert_eq!(u16::from(rsp.status()), 200);
		let body = rsp.into_body().collect_string().await.unwrap();
		assert!(!body.is_empty());

		let head = head_rx.await.unwrap();
		assert!(
			head.starts_with(&format!(
				"CONNECT token.test:{} HTTP/1.1\r\n",
				origin.address().port()
			)),
			"expected CONNECT handshake via proxy, got: {head}"
		);
	}
}
