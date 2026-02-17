use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use url::Url;
use std::time::Instant;

const RDAP_BOOTSTRAP_URL: &str = "https://data.iana.org/rdap/dns.json";

#[derive(Debug)]
pub(crate) struct RdapProbe {
    pub rdap_url: String,
    pub registrar: Option<String>,
    pub registrar_iana_id: Option<String>,
    pub registered_on: Option<DateTime<Utc>>,
    pub expires_on: Option<DateTime<Utc>>,
    pub status_codes: Vec<String>,
    pub registrant_name: Option<String>,
    pub registrant_contact_uri: Option<String>,
    pub abuse_email: Option<String>,
    pub abuse_phone: Option<String>,
    pub elapsed_ms: u128,
}

#[derive(Debug, Deserialize)]
struct RdapBootstrap {
    services: Vec<(Vec<String>, Vec<String>)>,
}

#[derive(Debug, Deserialize)]
struct RdapDomain {
    events: Option<Vec<RdapEvent>>,
    status: Option<Vec<String>>,
    entities: Option<Vec<RdapEntity>>,
    links: Option<Vec<RdapLink>>,
}

#[derive(Debug, Deserialize)]
struct RdapEvent {
    #[serde(rename = "eventAction")]
    event_action: String,
    #[serde(rename = "eventDate")]
    event_date: String,
}

#[derive(Debug, Deserialize)]
struct RdapEntity {
    roles: Option<Vec<String>>,
    entities: Option<Vec<RdapEntity>>,
    #[serde(rename = "vcardArray")]
    vcard_array: Option<Value>,
    #[serde(rename = "publicIds")]
    public_ids: Option<Vec<RdapPublicId>>,
}

#[derive(Debug, Deserialize)]
struct RdapLink {
    rel: Option<String>,
    href: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RdapPublicId {
    #[serde(rename = "type")]
    kind: Option<String>,
    identifier: Option<String>,
}

#[derive(Debug, Default)]
struct RdapEntityFields {
    registrar: Option<String>,
    registrar_iana_id: Option<String>,
    registrant_name: Option<String>,
    registrant_contact_uri: Option<String>,
    abuse_email: Option<String>,
    abuse_phone: Option<String>,
}

pub(crate) async fn probe_rdap(client: &Client, domain: &str) -> Result<RdapProbe> {
    let started = Instant::now();
    let tld = domain
        .rsplit('.')
        .next()
        .ok_or_else(|| anyhow!("domain `{domain}` has no TLD"))?
        .to_ascii_lowercase();

    let bootstrap = client
        .get(RDAP_BOOTSTRAP_URL)
        .send()
        .await
        .context("failed to fetch RDAP bootstrap")?
        .error_for_status()
        .context("RDAP bootstrap returned non-success")?
        .json::<RdapBootstrap>()
        .await
        .context("failed to parse RDAP bootstrap JSON")?;

    let rdap_base = bootstrap
        .services
        .into_iter()
        .find_map(|(tlds, urls)| {
            if tlds.iter().any(|entry| entry.eq_ignore_ascii_case(&tld)) {
                urls.first().cloned()
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow!("no RDAP service found for .{tld}"))?;

    let rdap_url = build_rdap_domain_url(&rdap_base, domain)?;

    let rdap_domain = client
        .get(&rdap_url)
        .send()
        .await
        .with_context(|| format!("failed to fetch RDAP domain record from {rdap_url}"))?
        .error_for_status()
        .context("RDAP domain endpoint returned non-success")?
        .json::<RdapDomain>()
        .await
        .context("failed to parse RDAP domain JSON")?;

    let events = rdap_domain.events.as_deref().unwrap_or(&[]);
    let registered_on = find_event_date(events, "registration");
    let expires_on = find_event_date(events, "expiration")
        .or_else(|| find_event_date(events, "expiry"))
        .or_else(|| find_event_date(events, "expiration date"));

    let mut entity_fields = extract_entity_fields(&rdap_domain);
    if needs_related_rdap(&entity_fields)
        && let Some(related_url) = find_related_rdap_url(&rdap_domain)
        && let Ok(resp) = client.get(&related_url).send().await
        && let Ok(resp) = resp.error_for_status()
        && let Ok(related_json) = resp.json::<Value>().await
    {
        let related_fields = extract_entity_fields_from_value(&related_json);
        merge_entity_fields(&mut entity_fields, related_fields);
    }

    let is_cloudflare_registrar = entity_fields
        .registrar
        .as_deref()
        .map(|name| name.to_ascii_lowercase().contains("cloudflare"))
        .unwrap_or(false);
    if is_cloudflare_registrar
        && needs_related_rdap(&entity_fields)
        && let Ok(resp) = client
            .get(format!(
                "https://rdap.cloudflare.com/rdap/v1/domain/{domain}"
            ))
            .send()
            .await
        && let Ok(resp) = resp.error_for_status()
        && let Ok(cloudflare_json) = resp.json::<Value>().await
    {
        let cloudflare_fields = extract_entity_fields_from_value(&cloudflare_json);
        merge_entity_fields(&mut entity_fields, cloudflare_fields);
    }

    Ok(RdapProbe {
        rdap_url,
        registrar: entity_fields.registrar,
        registrar_iana_id: entity_fields.registrar_iana_id,
        registered_on,
        expires_on,
        status_codes: rdap_domain.status.unwrap_or_default(),
        registrant_name: entity_fields.registrant_name,
        registrant_contact_uri: entity_fields.registrant_contact_uri,
        abuse_email: entity_fields.abuse_email,
        abuse_phone: entity_fields.abuse_phone,
        elapsed_ms: started.elapsed().as_millis(),
    })
}

fn build_rdap_domain_url(base: &str, domain: &str) -> Result<String> {
    let mut url = Url::parse(base).with_context(|| format!("invalid RDAP base URL: {base}"))?;
    if !url.path().ends_with('/') {
        let new_path = format!("{}/", url.path());
        url.set_path(&new_path);
    }
    Ok(url.join(&format!("domain/{domain}"))?.to_string())
}

fn find_event_date(events: &[RdapEvent], event: &str) -> Option<DateTime<Utc>> {
    events
        .iter()
        .find(|e| e.event_action.to_ascii_lowercase().contains(event))
        .and_then(|e| parse_rfc3339_utc(&e.event_date))
}

fn parse_rfc3339_utc(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn find_related_rdap_url(domain: &RdapDomain) -> Option<String> {
    domain.links.as_ref()?.iter().find_map(|link| {
        let is_related = link
            .rel
            .as_deref()
            .map(|v| v.eq_ignore_ascii_case("related"))
            .unwrap_or(false);
        if is_related { link.href.clone() } else { None }
    })
}

fn needs_related_rdap(fields: &RdapEntityFields) -> bool {
    fields.registrant_name.is_none()
        || fields.registrant_contact_uri.is_none()
        || fields.abuse_email.is_none()
}

fn merge_entity_fields(target: &mut RdapEntityFields, incoming: RdapEntityFields) {
    if target.registrar.is_none() {
        target.registrar = incoming.registrar;
    }
    if target.registrar_iana_id.is_none() {
        target.registrar_iana_id = incoming.registrar_iana_id;
    }
    if target.registrant_name.is_none() {
        target.registrant_name = incoming.registrant_name;
    }
    if target.registrant_contact_uri.is_none() {
        target.registrant_contact_uri = incoming.registrant_contact_uri;
    }
    if target.abuse_email.is_none() {
        target.abuse_email = incoming.abuse_email;
    }
    if target.abuse_phone.is_none() {
        target.abuse_phone = incoming.abuse_phone;
    }
}

fn extract_entity_fields(domain: &RdapDomain) -> RdapEntityFields {
    let mut flat_entities = Vec::new();
    if let Some(entities) = domain.entities.as_deref() {
        flatten_entities(entities, &mut flat_entities);
    }

    let registrar_entity = flat_entities
        .iter()
        .find(|entity| has_role(entity, "registrar"))
        .copied();
    let abuse_entity = flat_entities
        .iter()
        .find(|entity| has_role(entity, "abuse"))
        .copied();
    let registrant_entity = flat_entities
        .iter()
        .find(|entity| has_role(entity, "registrant"))
        .or_else(|| {
            flat_entities
                .iter()
                .find(|entity| has_role(entity, "administrative"))
        })
        .or_else(|| {
            flat_entities
                .iter()
                .find(|entity| has_role(entity, "technical"))
        })
        .copied();

    RdapEntityFields {
        registrar: registrar_entity.and_then(|e| first_vcard_value(e, "fn")),
        registrar_iana_id: registrar_entity.and_then(extract_iana_id),
        registrant_name: registrant_entity.and_then(|e| first_vcard_value(e, "fn")),
        registrant_contact_uri: registrant_entity.and_then(|e| first_vcard_value(e, "contact-uri")),
        abuse_email: abuse_entity.and_then(|e| first_vcard_value(e, "email")),
        abuse_phone: abuse_entity
            .and_then(|e| first_vcard_value(e, "tel"))
            .map(|tel| tel.trim_start_matches("tel:").to_string()),
    }
}

fn extract_entity_fields_from_value(root: &Value) -> RdapEntityFields {
    let mut entities_flat = Vec::new();
    if let Some(entities) = root.get("entities").and_then(Value::as_array) {
        flatten_entity_values(entities, &mut entities_flat);
    }

    let registrar = entities_flat
        .iter()
        .find(|entity| entity_has_role(entity, "registrar"))
        .copied();
    let abuse = entities_flat
        .iter()
        .find(|entity| entity_has_role(entity, "abuse"))
        .copied();
    let registrant = entities_flat
        .iter()
        .find(|entity| entity_has_role(entity, "registrant"))
        .or_else(|| {
            entities_flat
                .iter()
                .find(|entity| entity_has_role(entity, "administrative"))
        })
        .or_else(|| {
            entities_flat
                .iter()
                .find(|entity| entity_has_role(entity, "technical"))
        })
        .copied();

    RdapEntityFields {
        registrar: registrar.and_then(|e| entity_first_vcard_value(e, "fn")),
        registrar_iana_id: registrar.and_then(entity_iana_id),
        registrant_name: registrant.and_then(|e| entity_first_vcard_value(e, "fn")),
        registrant_contact_uri: registrant.and_then(|e| entity_first_vcard_value(e, "contact-uri")),
        abuse_email: abuse.and_then(|e| entity_first_vcard_value(e, "email")),
        abuse_phone: abuse
            .and_then(|e| entity_first_vcard_value(e, "tel"))
            .map(|tel| tel.trim_start_matches("tel:").to_string()),
    }
}

fn flatten_entity_values<'a>(entities: &'a [Value], out: &mut Vec<&'a Value>) {
    for entity in entities {
        if !entity.is_object() {
            continue;
        }
        out.push(entity);
        if let Some(children) = entity.get("entities").and_then(Value::as_array) {
            flatten_entity_values(children, out);
        }
    }
}

fn entity_has_role(entity: &Value, role: &str) -> bool {
    entity
        .get("roles")
        .and_then(Value::as_array)
        .map(|roles| {
            roles
                .iter()
                .filter_map(Value::as_str)
                .any(|entry| entry.eq_ignore_ascii_case(role))
        })
        .unwrap_or(false)
}

fn entity_first_vcard_value(entity: &Value, key: &str) -> Option<String> {
    let vcard = entity.get("vcardArray")?;
    vcard_values(vcard, key).into_iter().find(|v| !v.is_empty())
}

fn entity_iana_id(entity: &Value) -> Option<String> {
    entity
        .get("publicIds")
        .and_then(Value::as_array)
        .and_then(|ids| {
            ids.iter().find_map(|id| {
                let is_iana = id
                    .get("type")
                    .and_then(Value::as_str)
                    .map(|s| s.to_ascii_lowercase().contains("iana"))
                    .unwrap_or(false);
                if !is_iana {
                    return None;
                }
                id.get("identifier")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
        })
}

fn flatten_entities<'a>(entities: &'a [RdapEntity], out: &mut Vec<&'a RdapEntity>) {
    for entity in entities {
        out.push(entity);
        if let Some(children) = entity.entities.as_deref() {
            flatten_entities(children, out);
        }
    }
}

fn has_role(entity: &RdapEntity, role: &str) -> bool {
    entity
        .roles
        .as_ref()
        .map(|roles| roles.iter().any(|r| r.eq_ignore_ascii_case(role)))
        .unwrap_or(false)
}

fn extract_iana_id(entity: &RdapEntity) -> Option<String> {
    entity.public_ids.as_ref().and_then(|ids| {
        ids.iter().find_map(|id| {
            let is_iana = id
                .kind
                .as_deref()
                .map(|v| v.to_ascii_lowercase().contains("iana"))
                .unwrap_or(false);
            if is_iana { id.identifier.clone() } else { None }
        })
    })
}

fn first_vcard_value(entity: &RdapEntity, key: &str) -> Option<String> {
    let vcard = entity.vcard_array.as_ref()?;
    vcard_values(vcard, key).into_iter().find(|v| !v.is_empty())
}

fn vcard_values(vcard_array: &Value, key: &str) -> Vec<String> {
    let mut values = Vec::new();

    let rows = vcard_array
        .as_array()
        .and_then(|arr| arr.get(1))
        .and_then(Value::as_array);
    let Some(rows) = rows else {
        return values;
    };

    for row in rows {
        let Some(parts) = row.as_array() else {
            continue;
        };
        if parts.len() < 4 {
            continue;
        }

        let Some(name) = parts[0].as_str() else {
            continue;
        };
        if !name.eq_ignore_ascii_case(key) {
            continue;
        }

        if let Some(val) = parts[3].as_str() {
            let clean = val.trim().to_string();
            if !clean.is_empty() {
                values.push(clean);
            }
            continue;
        }

        if let Some(arr) = parts[3].as_array() {
            let joined = arr
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            if !joined.is_empty() {
                values.push(joined);
            }
        }
    }

    values
}
