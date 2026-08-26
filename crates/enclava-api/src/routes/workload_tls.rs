use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::{Json, response::IntoResponse};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CertificateRequest {
    hostnames: Vec<String>,
    csr_der_base64: String,
    cc_init_data_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct CertificateResponse {
    certificate_chain_pem: String,
}

#[derive(Debug, sqlx::FromRow)]
struct DescriptorRow {
    descriptor_payload: Value,
}

pub async fn dns01_certificate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CertificateRequest>,
) -> impl IntoResponse {
    let Some(token) = crate::routes::workload::attestation_bearer(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "attestation_token_required"})),
        )
            .into_response();
    };
    let Some(verify_url) = state.trustee_attestation_verify_url.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "trustee_attestation_verify_unconfigured"})),
        )
            .into_response();
    };
    let Some(dns_config) = state.dns.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "dns_management_unconfigured"})),
        )
            .into_response();
    };
    let Some(acme_config) = state.acme.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "acme_unconfigured"})),
        )
            .into_response();
    };

    let claims = match verify_attestation(&state, verify_url, token).await {
        Ok(claims) => claims,
        Err(response) => return *response,
    };
    let Some(descriptor_core_hash) = crate::routes::workload::extract_descriptor_core_hash(&claims)
    else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "descriptor_core_hash_missing"})),
        )
            .into_response();
    };
    let Some(init_data_hash) = attested_or_declared_init_data_hash(&claims, &body) else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "init_data_hash_missing"})),
        )
            .into_response();
    };

    let row = match sqlx::query_as::<_, DescriptorRow>(
        "SELECT descriptor_payload
         FROM workload_artifacts
         WHERE descriptor_core_hash = $1",
    )
    .bind(descriptor_core_hash)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "workload_artifacts_not_found"})),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({"error": "workload_artifacts_query_failed", "detail": err.to_string()}),
                ),
            )
                .into_response();
        }
    };

    if !descriptor_init_hash_matches(&row.descriptor_payload, &init_data_hash) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "attested_init_data_hash_mismatch"})),
        )
            .into_response();
    }
    if let Err(err) = validate_requested_hostnames(&row.descriptor_payload, &body.hostnames) {
        return (StatusCode::FORBIDDEN, Json(json!({"error": err}))).into_response();
    }
    let csr_der = match base64::engine::general_purpose::STANDARD.decode(&body.csr_der_base64) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        Ok(_) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "csr_empty"}))).into_response();
        }
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "csr_base64_invalid", "detail": err.to_string()})),
            )
                .into_response();
        }
    };

    match crate::acme::issue_dns01_certificate(
        &state.http_client,
        dns_config,
        acme_config,
        &body.hostnames,
        &csr_der,
    )
    .await
    {
        Ok(certificate_chain_pem) => (
            StatusCode::OK,
            Json(CertificateResponse {
                certificate_chain_pem,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "acme_certificate_issuance_failed", "detail": err.to_string()})),
        )
            .into_response(),
    }
}

fn attested_or_declared_init_data_hash(
    claims: &Value,
    body: &CertificateRequest,
) -> Option<Vec<u8>> {
    crate::routes::workload::extract_init_data_hash(claims).or_else(|| {
        body.cc_init_data_hash
            .as_deref()
            .and_then(crate::routes::workload::parse_hex32)
    })
}

async fn verify_attestation(
    state: &AppState,
    verify_url: &str,
    token: &str,
) -> Result<Value, Box<axum::response::Response>> {
    let verify_response = match crate::routes::workload::trustee_attestation_verify_request(
        &state.trustee_http_client,
        verify_url,
        token,
        state.trustee_attestation_verify_bearer_token.as_deref(),
    )
    .send()
    .await
    {
        Ok(response) => response,
        Err(err) => {
            return Err((
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "trustee_attestation_verify_failed", "detail": err.to_string()})),
            )
                .into_response()
                .into());
        }
    };

    if !verify_response.status().is_success() {
        let status = verify_response.status().as_u16();
        let body = verify_response.text().await.unwrap_or_default();
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "attestation_denied",
                "upstream_status": status,
                "upstream_body": body,
            })),
        )
            .into_response()
            .into());
    }

    verify_response.json().await.map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "attestation_claims_invalid", "detail": err.to_string()})),
        )
            .into_response()
            .into()
    })
}

fn descriptor_init_hash_matches(descriptor: &Value, attested_init_data_hash: &[u8]) -> bool {
    descriptor
        .get("expected_cc_init_data_hash")
        .and_then(Value::as_str)
        .and_then(crate::routes::workload::parse_hex32)
        .as_deref()
        == Some(attested_init_data_hash)
}

fn validate_requested_hostnames(descriptor: &Value, requested: &[String]) -> Result<(), String> {
    if requested.is_empty() {
        return Err("hostnames_empty".into());
    }
    let allowed = allowed_certificate_hostnames(descriptor);
    if allowed.is_empty() {
        return Err("descriptor_has_no_certificate_hostnames".into());
    }
    for hostname in requested {
        if !allowed.iter().any(|allowed| allowed == hostname) {
            return Err("hostname_not_attested".into());
        }
    }
    Ok(())
}

fn allowed_certificate_hostnames(descriptor: &Value) -> Vec<String> {
    let mut hostnames = Vec::new();
    if let Some(hostname) = descriptor.get("app_domain").and_then(Value::as_str)
        && !hostname.is_empty()
    {
        hostnames.push(hostname.to_string());
    }
    if let Some(custom) = descriptor.get("custom_domains").and_then(Value::as_array) {
        for hostname in custom.iter().filter_map(Value::as_str) {
            if !hostname.is_empty() && !hostnames.iter().any(|existing| existing == hostname) {
                hostnames.push(hostname.to_string());
            }
        }
    }
    hostnames
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_hostnames_are_limited_to_attested_descriptor_domains() {
        let descriptor = json!({
            "app_domain": "app.enclava.dev",
            "tee_domain": "app.tee.enclava.dev",
            "custom_domains": ["custom.example.test"]
        });

        assert!(validate_requested_hostnames(&descriptor, &["app.enclava.dev".into()]).is_ok());
        assert!(validate_requested_hostnames(&descriptor, &["custom.example.test".into()]).is_ok());
        assert_eq!(
            validate_requested_hostnames(&descriptor, &["other.example.test".into()]).unwrap_err(),
            "hostname_not_attested"
        );
    }

    #[test]
    fn broker_accepts_declared_cc_init_data_hash_when_kbs_token_omits_it() {
        let body = CertificateRequest {
            hostnames: vec!["app.enclava.dev".into()],
            csr_der_base64: "AA==".into(),
            cc_init_data_hash: Some("ab".repeat(32)),
        };

        assert_eq!(
            attested_or_declared_init_data_hash(&json!({}), &body),
            Some(vec![0xab; 32])
        );
    }
}
