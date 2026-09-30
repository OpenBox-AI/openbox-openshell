//! Front desk policy: what the governance interceptor stamps onto new
//! sandboxes and which changes it refuses.
//!
//! The invariant it keeps: every sandbox in a governed gateway sends all of
//! its inspectable egress through the `OpenBox` verdict middleware, and
//! nothing turns that off afterwards.
//!
//! - `CreateSandbox` (`modify_operation`): attach `network_middlewares.openbox`
//!   selecting every host (`**`), `fail_closed`, and label the sandbox as
//!   governed. Hosts on `tls: skip` endpoints cannot be inspected, and
//!   `OpenShell` refuses a fail-closed middleware that selects them, so they
//!   are excluded explicitly and reported as a coverage gap.
//! - `CreateSandbox` and `UpdateConfig` (`validate`): refuse a policy whose
//!   attachment is missing or weakened, any endpoint that sends credentials
//!   uninspected (`allow_uninspected_credentials`), and turning on automatic
//!   approval of agent-authored policy proposals.
//! - `ImportProviderProfiles` and `UpdateProviderProfiles` (`validate`):
//!   refuse a profile endpoint that sends credentials uninspected. A
//!   provider's profile endpoints are composed into the sandbox's effective
//!   policy when it is attached, so they never pass the policy checks above.
//!   Since `OpenShell` v0.1.2 every profile enters through these two RPCs
//!   (the built-in source was removed), so `AttachSandboxProvider`, which
//!   only names a provider, can only reach profiles that were checked here.
//!
//! Operations arrive as canonical `ProtoJSON` (lowerCamelCase field names,
//! enums as names); patches are RFC 6902 against the same shape.

use serde_json::{Map, Value, json};

pub const ATTACHMENT_KEY: &str = "openbox";
pub const MIDDLEWARE_NAME: &str = "openbox";
pub const GOVERNED_LABEL: &str = "openbox.ai/governed";
const ALL_HOSTS: &str = "**";
const TLS_SKIP: &str = "NETWORK_TLS_MODE_SKIP";
/// Default position in the middleware chain: after operator middleware
/// (redaction and similar), so the verdict covers what actually leaves.
const DEFAULT_ORDER: i64 = 1000;

/// One RFC 6902 operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Patch {
    pub op: &'static str,
    pub path: String,
    pub value: Value,
}

/// Refusal with a message safe to show to the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal(pub String);

fn field<'a>(object: &'a Value, camel: &str, snake: &str) -> Option<&'a Value> {
    object.get(camel).or_else(|| object.get(snake))
}

fn network_policies(policy: &Value) -> impl Iterator<Item = &Value> {
    field(policy, "networkPolicies", "network_policies")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(Map::values)
}

fn endpoints(rule: &Value) -> impl Iterator<Item = &Value> {
    rule.get("endpoints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn is_tls_skip(endpoint: &Value) -> bool {
    match endpoint.get("tls") {
        Some(Value::String(mode)) => mode == TLS_SKIP || mode.eq_ignore_ascii_case("skip"),
        Some(Value::Number(mode)) => mode.as_i64() == Some(1),
        _ => false,
    }
}

fn sends_uninspected_credentials(endpoint: &Value) -> bool {
    field(
        endpoint,
        "allowUninspectedCredentials",
        "allow_uninspected_credentials",
    )
    .and_then(Value::as_bool)
    .unwrap_or(false)
}

/// Hosts that no middleware can inspect, sorted and de-duplicated.
pub fn uninspectable_hosts(policy: &Value) -> Vec<String> {
    let mut hosts: Vec<String> = network_policies(policy)
        .flat_map(endpoints)
        .filter(|endpoint| is_tls_skip(endpoint))
        .filter_map(|endpoint| endpoint.get("host").and_then(Value::as_str))
        .map(str::to_ascii_lowercase)
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

fn refuse_uninspected_credentials<'a>(
    mut endpoints: impl Iterator<Item = &'a Value>,
) -> Result<(), Refusal> {
    endpoints
        .find(|endpoint| sends_uninspected_credentials(endpoint))
        .map_or(Ok(()), |endpoint| {
            Err(Refusal(format!(
                "OpenBox governance does not allow credentials to uninspected traffic (host {})",
                endpoint.get("host").and_then(Value::as_str).unwrap_or("?")
            )))
        })
}

/// The attachment the front desk requires on a policy.
pub fn required_attachment(policy: &Value) -> Value {
    let order = field(policy, "networkMiddlewares", "network_middlewares")
        .and_then(Value::as_object)
        .map_or(DEFAULT_ORDER, |existing| {
            let taken: Vec<i64> = existing
                .iter()
                .filter(|(key, _)| key.as_str() != ATTACHMENT_KEY)
                .filter_map(|(_, config)| config.get("order").and_then(Value::as_i64))
                .collect();
            let mut order = taken
                .iter()
                .copied()
                .max()
                .map_or(DEFAULT_ORDER, |max| DEFAULT_ORDER.max(max + 10));
            while taken.contains(&order) {
                order += 1;
            }
            order
        });
    let mut endpoints = json!({ "include": [ALL_HOSTS] });
    let excluded = uninspectable_hosts(policy);
    if !excluded.is_empty() {
        endpoints["exclude"] = json!(excluded);
    }
    json!({
        "name": "OpenBox verdicts",
        "middleware": MIDDLEWARE_NAME,
        "config": { "approval_mode": "queue" },
        "onError": "fail_closed",
        "endpoints": endpoints,
        "order": order,
    })
}

/// Patches for `CreateSandbox` in `modify_operation`.
pub fn modify_create_sandbox(operation: &Value) -> Result<Vec<Patch>, Refusal> {
    let spec = operation.get("spec");
    let policy = spec.and_then(|spec| spec.get("policy"));
    let mut patches = Vec::new();
    match policy {
        Some(policy) if policy.is_object() => {
            refuse_uninspected_credentials(network_policies(policy).flat_map(endpoints))?;
            let mut middlewares = field(policy, "networkMiddlewares", "network_middlewares")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            middlewares.remove("network_middlewares");
            middlewares.insert(ATTACHMENT_KEY.to_owned(), required_attachment(policy));
            // `add` replaces an existing member, so this is idempotent.
            patches.push(Patch {
                op: "add",
                path: "/spec/policy/networkMiddlewares".to_owned(),
                value: Value::Object(middlewares),
            });
        }
        // No policy yet: the gateway fills in its default. Without network
        // policies there is no egress for the middleware to govern, and the
        // validate phase still checks whatever the gateway prepared.
        _ => {}
    }
    let labels_path = if operation.get("labels").is_some_and(Value::is_object) {
        format!(
            "/labels/{}",
            GOVERNED_LABEL.replace('~', "~0").replace('/', "~1")
        )
    } else {
        String::new()
    };
    if labels_path.is_empty() {
        patches.push(Patch {
            op: "add",
            path: "/labels".to_owned(),
            value: json!({ GOVERNED_LABEL: "true" }),
        });
    } else {
        patches.push(Patch {
            op: "add",
            path: labels_path,
            value: json!("true"),
        });
    }
    Ok(patches)
}

/// Checks that a policy still carries a complete `OpenBox` attachment.
pub fn validate_policy(policy: &Value) -> Result<(), Refusal> {
    refuse_uninspected_credentials(network_policies(policy).flat_map(endpoints))?;
    if network_policies(policy).next().is_none() {
        // No egress at all: nothing to govern.
        return Ok(());
    }
    let attachment = field(policy, "networkMiddlewares", "network_middlewares")
        .and_then(|middlewares| middlewares.get(ATTACHMENT_KEY))
        .ok_or_else(|| {
            Refusal("the OpenBox middleware must stay attached (every governed sandbox policy carries it)".to_owned())
        })?;
    if attachment.get("middleware").and_then(Value::as_str) != Some(MIDDLEWARE_NAME) {
        return Err(Refusal(
            "the OpenBox attachment must use the OpenBox middleware".to_owned(),
        ));
    }
    let on_error = field(attachment, "onError", "on_error")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !on_error.is_empty() && on_error != "fail_closed" {
        return Err(Refusal(
            "the OpenBox middleware must fail closed".to_owned(),
        ));
    }
    let selector = attachment.get("endpoints").cloned().unwrap_or_default();
    let list = |key: &str| -> Vec<String> {
        selector
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_ascii_lowercase)
            .collect()
    };
    if !list("include").iter().any(|pattern| pattern == ALL_HOSTS) {
        return Err(Refusal(
            "the OpenBox middleware must select every host".to_owned(),
        ));
    }
    let allowed = uninspectable_hosts(policy);
    if let Some(extra) = list("exclude")
        .into_iter()
        .find(|host| !allowed.contains(host))
    {
        return Err(Refusal(format!(
            "the OpenBox middleware may only exclude uninspectable hosts (not {extra})"
        )));
    }
    if let Some(mode) = attachment
        .get("config")
        .and_then(|config| config.get("approval_mode"))
        .and_then(Value::as_str)
        && mode != "queue"
        && mode != "deny"
    {
        return Err(Refusal(
            "the OpenBox approval_mode must be queue or deny".to_owned(),
        ));
    }
    Ok(())
}

/// `CreateSandbox` in `validate`: the prepared operation after every
/// interceptor's modifications.
pub fn validate_create_sandbox(operation: &Value) -> Result<(), Refusal> {
    operation
        .get("spec")
        .and_then(|spec| spec.get("policy"))
        .map_or(Ok(()), validate_policy)
}

/// `UpdateConfig` in `validate`.
pub fn validate_update_config(operation: &Value) -> Result<(), Refusal> {
    let setting_key = field(operation, "settingKey", "setting_key").and_then(Value::as_str);
    let setting_value = field(operation, "settingValue", "setting_value")
        .and_then(|value| field(value, "stringValue", "string_value"))
        .and_then(Value::as_str);
    if setting_key == Some("proposal_approval_mode") && setting_value == Some("auto") {
        return Err(Refusal(
            "automatic approval of agent policy proposals is disabled by OpenBox governance"
                .to_owned(),
        ));
    }
    if let Some(policy) = operation.get("policy").filter(|policy| !policy.is_null()) {
        validate_policy(policy)?;
    }
    let merges = field(operation, "mergeOperations", "merge_operations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    for merge in merges {
        // AddNetworkRule carries a full rule; the other merge kinds only
        // narrow or reference existing rules.
        let added = field(merge, "addRule", "add_rule")
            .and_then(|add| add.get("rule"))
            .into_iter()
            .flat_map(endpoints);
        refuse_uninspected_credentials(added)?;
    }
    Ok(())
}

fn profile_endpoints(item: &Value) -> impl Iterator<Item = &Value> {
    item.get("profile")
        .and_then(|profile| profile.get("endpoints"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

/// `ImportProviderProfiles` in `validate`.
pub fn validate_import_provider_profiles(operation: &Value) -> Result<(), Refusal> {
    let items = operation
        .get("profiles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    refuse_uninspected_credentials(items.flat_map(profile_endpoints))
}

/// `UpdateProviderProfiles` in `validate`.
pub fn validate_update_provider_profiles(operation: &Value) -> Result<(), Refusal> {
    refuse_uninspected_credentials(
        operation
            .get("profile")
            .into_iter()
            .flat_map(profile_endpoints),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Value {
        json!({
            "version": 1,
            "networkPolicies": {
                "api": {
                    "name": "api",
                    "endpoints": [
                        {"host": "api.example.com", "port": 443},
                        {"host": "Legacy.Example.com", "port": 443, "tls": "NETWORK_TLS_MODE_SKIP"}
                    ],
                    "binaries": [{"path": "/usr/bin/curl"}]
                }
            }
        })
    }

    fn apply(operation: &Value, patches: &[Patch]) -> Value {
        let mut operation = operation.clone();
        for patch in patches {
            let (parent, key) = patch.path.rsplit_once('/').unwrap();
            let key = key.replace("~1", "/").replace("~0", "~");
            let target = if parent.is_empty() {
                &mut operation
            } else {
                operation.pointer_mut(parent).unwrap()
            };
            target
                .as_object_mut()
                .unwrap()
                .insert(key, patch.value.clone());
        }
        operation
    }

    #[test]
    fn create_attaches_openbox_to_every_inspectable_host_and_labels_the_sandbox() {
        let operation = json!({"name": "sbx", "spec": {"policy": policy()}});
        let patched = apply(&operation, &modify_create_sandbox(&operation).unwrap());
        let attachment = &patched["spec"]["policy"]["networkMiddlewares"]["openbox"];
        assert_eq!(attachment["middleware"], "openbox");
        assert_eq!(attachment["onError"], "fail_closed");
        assert_eq!(attachment["endpoints"]["include"], json!(["**"]));
        assert_eq!(
            attachment["endpoints"]["exclude"],
            json!(["legacy.example.com"])
        );
        assert_eq!(patched["labels"][GOVERNED_LABEL], "true");
        assert_eq!(validate_create_sandbox(&patched), Ok(()));
    }

    #[test]
    fn create_keeps_other_middleware_and_orders_openbox_after_it() {
        let mut policy = policy();
        policy["networkMiddlewares"] = json!({
            "redactor": {"middleware": "openshell/regex", "order": 1200, "endpoints": {"include": ["**"]}}
        });
        let operation = json!({"spec": {"policy": policy}, "labels": {"team": "a"}});
        let patched = apply(&operation, &modify_create_sandbox(&operation).unwrap());
        let middlewares = &patched["spec"]["policy"]["networkMiddlewares"];
        assert_eq!(middlewares["redactor"]["order"], 1200);
        assert_eq!(middlewares["openbox"]["order"], 1210);
        assert_eq!(patched["labels"]["team"], "a");
        assert_eq!(patched["labels"][GOVERNED_LABEL], "true");
    }

    #[test]
    fn create_replaces_a_weakened_openbox_entry() {
        let mut policy = policy();
        policy["networkMiddlewares"] = json!({
            "openbox": {"middleware": "openbox", "onError": "fail_open", "endpoints": {"include": ["api.example.com"]}}
        });
        let operation = json!({"spec": {"policy": policy}});
        let patched = apply(&operation, &modify_create_sandbox(&operation).unwrap());
        assert_eq!(validate_create_sandbox(&patched), Ok(()));
        assert_eq!(
            patched["spec"]["policy"]["networkMiddlewares"]["openbox"]["onError"],
            "fail_closed"
        );
    }

    #[test]
    fn create_refuses_uninspected_credentials() {
        let mut policy = policy();
        policy["networkPolicies"]["api"]["endpoints"][1]["allowUninspectedCredentials"] =
            json!(true);
        let operation = json!({"spec": {"policy": policy}});
        assert!(modify_create_sandbox(&operation).is_err());
        assert!(validate_create_sandbox(&operation).is_err());
    }

    #[test]
    fn a_policy_without_egress_needs_no_attachment() {
        let operation = json!({"spec": {"policy": {"version": 1}}});
        assert_eq!(validate_create_sandbox(&operation), Ok(()));
        let operation = json!({"spec": {}});
        let patches = modify_create_sandbox(&operation).unwrap();
        assert_eq!(patches.len(), 1, "only the label");
    }

    #[test]
    fn validation_catches_every_way_to_weaken_the_attachment() {
        let good = {
            let operation = json!({"spec": {"policy": policy()}});
            apply(&operation, &modify_create_sandbox(&operation).unwrap())["spec"]["policy"].clone()
        };
        assert_eq!(validate_policy(&good), Ok(()));
        let weaken = |path: &str, value: Value| {
            let mut policy = good.clone();
            *policy.pointer_mut(path).unwrap() = value;
            validate_policy(&policy)
        };
        assert!(weaken("/networkMiddlewares", json!({})).is_err(), "removed");
        assert!(weaken("/networkMiddlewares/openbox/middleware", json!("other")).is_err());
        assert!(weaken("/networkMiddlewares/openbox/onError", json!("fail_open")).is_err());
        assert!(
            weaken(
                "/networkMiddlewares/openbox/endpoints/include",
                json!(["api.example.com"])
            )
            .is_err()
        );
        assert!(
            weaken(
                "/networkMiddlewares/openbox/endpoints/exclude",
                json!(["legacy.example.com", "api.example.com"])
            )
            .is_err(),
            "excluding an inspectable host"
        );
        assert!(
            weaken(
                "/networkMiddlewares/openbox/config",
                json!({"approval_mode": "off"})
            )
            .is_err()
        );
    }

    #[test]
    fn update_config_is_checked_the_same_way() {
        let good = {
            let operation = json!({"spec": {"policy": policy()}});
            apply(&operation, &modify_create_sandbox(&operation).unwrap())["spec"]["policy"].clone()
        };
        assert_eq!(
            validate_update_config(&json!({"sandbox": "s", "policy": good})),
            Ok(())
        );
        assert!(validate_update_config(&json!({"sandbox": "s", "policy": policy()})).is_err());
        assert!(
            validate_update_config(&json!({
                "settingKey": "proposal_approval_mode",
                "settingValue": {"stringValue": "auto"}
            }))
            .is_err()
        );
        assert_eq!(
            validate_update_config(&json!({
                "settingKey": "proposal_approval_mode",
                "settingValue": {"stringValue": "manual"}
            })),
            Ok(())
        );
        assert!(
            validate_update_config(&json!({"mergeOperations": [{"addRule": {"ruleName": "x", "rule": {
                "endpoints": [{"host": "x.example", "port": 443, "allowUninspectedCredentials": true}]
            }}}]}))
            .is_err()
        );
        assert_eq!(
            validate_update_config(
                &json!({"mergeOperations": [{"addRule": {"ruleName": "x", "rule": {
                    "endpoints": [{"host": "x.example", "port": 443}]
                }}}]})
            ),
            Ok(()),
            "new hosts are covered by the ** selector"
        );
    }

    #[test]
    fn accepts_snake_case_field_names_too() {
        let policy = json!({
            "network_policies": {"api": {"endpoints": [{"host": "a.example", "port": 443}]}},
            "network_middlewares": {"openbox": {
                "middleware": "openbox", "on_error": "fail_closed", "endpoints": {"include": ["**"]}
            }}
        });
        assert_eq!(validate_policy(&policy), Ok(()));
    }

    #[test]
    fn provider_profiles_may_not_send_credentials_uninspected() {
        // The shape of OpenShell's example copilot profile.
        let copilot = json!({"profile": {"id": "copilot", "endpoints": [
            {"host": "api.githubcopilot.com", "port": 443, "protocol": "rest"},
            {"host": "telemetry.enterprise.githubcopilot.com", "port": 443,
             "allowUninspectedCredentials": true}
        ]}, "source": "copilot.yaml"});
        let github = json!({"profile": {"id": "github", "endpoints": [
            {"host": "api.github.com", "port": 443, "protocol": "rest"}
        ]}});
        let refused = validate_import_provider_profiles(
            &json!({"profiles": [github, copilot]}),
        )
        .unwrap_err();
        assert!(
            refused.0.contains("telemetry.enterprise.githubcopilot.com"),
            "{refused:?}"
        );
        assert_eq!(
            validate_import_provider_profiles(&json!({"profiles": [github]})),
            Ok(())
        );
        assert_eq!(validate_import_provider_profiles(&json!({})), Ok(()));

        assert!(
            validate_update_provider_profiles(&json!({"id": "copilot", "profile": copilot}))
                .is_err()
        );
        assert_eq!(
            validate_update_provider_profiles(&json!({"id": "github", "profile": github})),
            Ok(())
        );
        assert!(
            validate_update_provider_profiles(&json!({"profile": {"profile": {"endpoints": [
                {"host": "x.example", "port": 443, "allow_uninspected_credentials": true}
            ]}}}))
            .is_err(),
            "snake case too"
        );
    }
}
