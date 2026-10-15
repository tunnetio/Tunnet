use crate::error::PostureError;
use crate::value::PostureValue;
use regex::Regex;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PostureOp {
    Eq,
    NotEq,
    In,
    NotIn,
    Gte,
    Gt,
    Lte,
    Lt,
    IsSet,
    NotSet,
    Matches,
    Contains,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostureAssertion {
    pub attribute: String,
    pub operator: PostureOp,
    pub value: Option<PostureValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostureResult {
    pub passed: bool,
    pub failing_assertions: Vec<PostureAssertion>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostureEvalSummary {
    pub passed: bool,
    pub results: HashMap<String, PostureResult>,
}

static ASSERTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)^\s*
        (?P<attr>[a-zA-Z][a-zA-Z0-9_:]*(?:\([^)]*\))?)
        \s+
        (?P<op>==|!=|>=|<=|>|<|IN|NOT\s+IN|IS\s+SET|IS\s+NOT\s+SET|MATCHES|CONTAINS)
        (?:\s+(?P<val>.+))?
        \s*$",
    )
    .expect("valid assertion regex")
});

static FUNC_ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([a-zA-Z][a-zA-Z0-9_:]*)\(([^)]*)\)$").expect("valid func attr regex")
});

/// Parse an assertion string like `device:diskEncryption == true`.
pub fn parse_assertion(input: &str) -> Result<PostureAssertion, PostureError> {
    let trimmed = input.trim();
    let caps = ASSERTION_RE
        .captures(trimmed)
        .ok_or_else(|| PostureError::InvalidAssertion(trimmed.to_string()))?;

    let raw_attr = caps.name("attr").map(|m| m.as_str().trim()).unwrap_or("");
    let attribute = normalize_attribute_key(raw_attr);

    let op_str = caps.name("op").map(|m| m.as_str()).unwrap_or("");
    let operator = parse_operator(op_str)?;

    let value = match operator {
        PostureOp::IsSet | PostureOp::NotSet => None,
        _ => {
            let val_str = caps.name("val").map(|m| m.as_str().trim()).ok_or_else(|| {
                PostureError::InvalidAssertion(format!("missing value in: {trimmed}"))
            })?;
            Some(parse_value(val_str)?)
        }
    };

    Ok(PostureAssertion {
        attribute,
        operator,
        value,
    })
}

/// Parse multiple assertion strings.
pub fn parse_assertions(inputs: &[&str]) -> Result<Vec<PostureAssertion>, PostureError> {
    inputs.iter().map(|s| parse_assertion(s)).collect()
}

fn normalize_attribute_key(raw: &str) -> String {
    if let Some(caps) = FUNC_ATTR_RE.captures(raw) {
        let base = caps.get(1).map(|m| m.as_str()).unwrap_or(raw);
        let arg = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let arg = unquote(arg);
        return format!("{base}:{arg}");
    }
    raw.to_string()
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    ['\'', '"']
        .into_iter()
        .find_map(|quote| s.strip_prefix(quote)?.strip_suffix(quote))
        .unwrap_or(s)
        .to_string()
}

fn parse_operator(s: &str) -> Result<PostureOp, PostureError> {
    match s.to_uppercase().as_str() {
        "==" => Ok(PostureOp::Eq),
        "!=" => Ok(PostureOp::NotEq),
        "IN" => Ok(PostureOp::In),
        "NOT IN" => Ok(PostureOp::NotIn),
        ">=" => Ok(PostureOp::Gte),
        ">" => Ok(PostureOp::Gt),
        "<=" => Ok(PostureOp::Lte),
        "<" => Ok(PostureOp::Lt),
        "IS SET" => Ok(PostureOp::IsSet),
        "IS NOT SET" => Ok(PostureOp::NotSet),
        "MATCHES" => Ok(PostureOp::Matches),
        "CONTAINS" => Ok(PostureOp::Contains),
        _ => Err(PostureError::InvalidAssertion(format!(
            "unknown operator: {s}"
        ))),
    }
}

fn parse_value(s: &str) -> Result<PostureValue, PostureError> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("true") {
        return Ok(PostureValue::Bool(true));
    }
    if s.eq_ignore_ascii_case("false") {
        return Ok(PostureValue::Bool(false));
    }
    if let Ok(n) = s.parse::<f64>() {
        return Ok(PostureValue::Number(n));
    }
    if s.starts_with('[') && s.ends_with(']') {
        let inner = &s[1..s.len() - 1];
        let items: Vec<String> = inner
            .split(',')
            .map(|item| unquote(item.trim()))
            .filter(|item| !item.is_empty())
            .collect();
        return Ok(PostureValue::StringList(items));
    }
    Ok(PostureValue::String(unquote(s)))
}

impl PostureAssertion {
    pub fn evaluate(&self, attributes: &HashMap<String, PostureValue>) -> bool {
        let actual = resolve_attribute(attributes, &self.attribute);

        match self.operator {
            PostureOp::IsSet => actual.is_some(),
            PostureOp::NotSet => actual.is_none(),
            PostureOp::Eq => actual == self.value.as_ref(),
            PostureOp::NotEq => actual != self.value.as_ref(),
            PostureOp::In => {
                let Some(actual) = actual else { return false };
                let Some(PostureValue::StringList(list)) = self.value.as_ref() else {
                    return false;
                };
                match actual {
                    PostureValue::String(s) => list.contains(s),
                    _ => false,
                }
            }
            PostureOp::NotIn => {
                let Some(actual) = actual else { return true };
                let Some(PostureValue::StringList(list)) = self.value.as_ref() else {
                    return false;
                };
                match actual {
                    PostureValue::String(s) => !list.contains(s),
                    _ => false,
                }
            }
            PostureOp::Gte | PostureOp::Gt | PostureOp::Lte | PostureOp::Lt => {
                let Some(actual) = actual else { return false };
                let Some(expected) = self.value.as_ref() else {
                    return false;
                };
                compare_ordered(actual, expected, self.operator)
            }
            PostureOp::Matches => {
                let Some(actual) = actual else { return false };
                let Some(PostureValue::String(pattern)) = self.value.as_ref() else {
                    return false;
                };
                let Some(s) = actual.as_str() else {
                    return false;
                };
                Regex::new(pattern)
                    .map(|re| re.is_match(s))
                    .unwrap_or(false)
            }
            PostureOp::Contains => {
                let Some(actual) = actual else { return false };
                let Some(expected) = self.value.as_ref() else {
                    return false;
                };
                match (actual, expected) {
                    (PostureValue::StringList(list), PostureValue::String(needle)) => {
                        list.iter().any(|s| s == needle)
                    }
                    (PostureValue::String(haystack), PostureValue::String(needle)) => {
                        haystack.contains(needle.as_str())
                    }
                    _ => false,
                }
            }
        }
    }
}

fn resolve_attribute<'a>(
    attributes: &'a HashMap<String, PostureValue>,
    key: &str,
) -> Option<&'a PostureValue> {
    if let Some(v) = attributes.get(key) {
        return Some(v);
    }
    // Also try function-style lookup: device:appRunning:x from device:appRunning('x')
    if let Some(caps) = FUNC_ATTR_RE.captures(key) {
        let base = caps.get(1).map(|m| m.as_str()).unwrap_or(key);
        let arg = unquote(caps.get(2).map(|m| m.as_str()).unwrap_or(""));
        let flat = format!("{base}:{arg}");
        if let Some(v) = attributes.get(&flat) {
            return Some(v);
        }
    }
    None
}

fn compare_ordered(actual: &PostureValue, expected: &PostureValue, op: PostureOp) -> bool {
    let actual_str = value_as_compare_string(actual);
    let expected_str = value_as_compare_string(expected);

    if let (Some(a), Some(e)) = (
        Version::parse(&normalize_version(&actual_str)).ok(),
        Version::parse(&normalize_version(&expected_str)).ok(),
    ) {
        return match op {
            PostureOp::Gte => a >= e,
            PostureOp::Gt => a > e,
            PostureOp::Lte => a <= e,
            PostureOp::Lt => a < e,
            _ => false,
        };
    }

    if let (Some(a), Some(e)) = (actual.as_number(), expected.as_number()) {
        return match op {
            PostureOp::Gte => a >= e,
            PostureOp::Gt => a > e,
            PostureOp::Lte => a <= e,
            PostureOp::Lt => a < e,
            _ => false,
        };
    }

    match op {
        PostureOp::Gte => actual_str >= expected_str,
        PostureOp::Gt => actual_str > expected_str,
        PostureOp::Lte => actual_str <= expected_str,
        PostureOp::Lt => actual_str < expected_str,
        _ => false,
    }
}

fn value_as_compare_string(v: &PostureValue) -> String {
    match v {
        PostureValue::String(s) => s.clone(),
        PostureValue::Number(n) => n.to_string(),
        PostureValue::Bool(b) => b.to_string(),
        PostureValue::StringList(list) => list.join(","),
    }
}

fn normalize_version(s: &str) -> String {
    let s = s.trim().trim_start_matches('v');
    let parts: Vec<&str> = s.split('.').collect();
    match parts.len() {
        0 => "0.0.0".into(),
        1 => format!("{}.0.0", parts[0]),
        2 => format!("{}.{}.0", parts[0], parts[1]),
        _ => s.to_string(),
    }
}

/// Evaluate a posture (AND logic across assertions).
pub fn evaluate_posture(
    posture: &[PostureAssertion],
    device_attributes: &HashMap<String, PostureValue>,
) -> PostureResult {
    let mut failures = Vec::new();
    for assertion in posture {
        if !assertion.evaluate(device_attributes) {
            failures.push(assertion.clone());
        }
    }
    PostureResult {
        passed: failures.is_empty(),
        failing_assertions: failures,
    }
}

/// Evaluate named postures. Each posture uses AND; the summary passes if any named posture passes (OR).
pub fn evaluate_named_postures(
    postures: &HashMap<String, Vec<PostureAssertion>>,
    names: &[String],
    attrs: &HashMap<String, PostureValue>,
) -> PostureEvalSummary {
    let mut results = HashMap::new();
    for name in names {
        if let Some(assertions) = postures.get(name) {
            results.insert(name.clone(), evaluate_posture(assertions, attrs));
        } else {
            results.insert(
                name.clone(),
                PostureResult {
                    passed: false,
                    failing_assertions: vec![],
                },
            );
        }
    }

    let passed = results.values().any(|r| r.passed);
    PostureEvalSummary { passed, results }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn attrs(pairs: &[(&str, PostureValue)]) -> HashMap<String, PostureValue> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[rstest]
    #[case::boolean_equality(
        "device:diskEncryption == true",
        "device:diskEncryption",
        PostureOp::Eq,
        Some(PostureValue::Bool(true))
    )]
    #[case::membership(
        "node:os IN ['macos', 'windows']",
        "node:os",
        PostureOp::In,
        Some(PostureValue::StringList(vec!["macos".into(), "windows".into()]))
    )]
    #[case::version_comparison(
        "node:tunnetVersion >= '0.7.0'",
        "node:tunnetVersion",
        PostureOp::Gte,
        Some(PostureValue::String("0.7.0".into()))
    )]
    #[case::presence(
        "device:antivirusName IS SET",
        "device:antivirusName",
        PostureOp::IsSet,
        None
    )]
    fn parses_assertion_forms(
        #[case] input: &str,
        #[case] expected_attribute: &str,
        #[case] expected_operator: PostureOp,
        #[case] expected_value: Option<PostureValue>,
    ) {
        let assertion = parse_assertion(input).unwrap();
        assert_eq!(assertion.attribute, expected_attribute);
        assert_eq!(assertion.operator, expected_operator);
        assert_eq!(assertion.value, expected_value);
    }

    #[test]
    fn parse_function_style_attribute() {
        let a = parse_assertion("device:fileExists('/etc/x') == true").unwrap();
        assert_eq!(a.attribute, "device:fileExists:/etc/x");
        assert_eq!(a.operator, PostureOp::Eq);
        assert_eq!(a.value, Some(PostureValue::Bool(true)));
    }

    #[rstest]
    #[case::lone_single_quote("device:x == '", "device:x", PostureValue::String("'".into()))]
    #[case::lone_double_quote("device:x == \"", "device:x", PostureValue::String("\"".into()))]
    #[case::empty_quoted("device:x == ''", "device:x", PostureValue::String(String::new()))]
    #[case::lone_quote_list_item(
        "device:x IN [']",
        "device:x",
        PostureValue::StringList(vec!["'".into()])
    )]
    #[case::lone_quote_function_arg(
        "device:fileExists(') == true",
        "device:fileExists:'",
        PostureValue::Bool(true)
    )]
    fn parses_unbalanced_quotes_verbatim(
        #[case] input: &str,
        #[case] expected_attribute: &str,
        #[case] expected_value: PostureValue,
    ) {
        let assertion = parse_assertion(input).unwrap();
        assert_eq!(assertion.attribute, expected_attribute);
        assert_eq!(assertion.value, Some(expected_value));
    }

    #[test]
    fn parse_app_running_attribute() {
        let a = parse_assertion("device:appRunning('com.crowdstrike.falcon') == true").unwrap();
        assert_eq!(a.attribute, "device:appRunning:com.crowdstrike.falcon");
    }

    #[rstest]
    #[case::member("node:os IN ['macos', 'windows']", "node:os", "macos", true)]
    #[case::not_a_member("node:os IN ['macos', 'windows']", "node:os", "linux", false)]
    #[case::newer_version("node:tunnetVersion >= '0.7.0'", "node:tunnetVersion", "0.8.0", true)]
    #[case::equal_version("node:tunnetVersion >= '0.7.0'", "node:tunnetVersion", "0.7", true)]
    #[case::older_version("node:tunnetVersion >= '0.7.0'", "node:tunnetVersion", "0.6.9", false)]
    fn evaluates_string_and_version_comparisons(
        #[case] expression: &str,
        #[case] attribute: &str,
        #[case] actual: &str,
        #[case] expected: bool,
    ) {
        let assertion = parse_assertion(expression).unwrap();
        let device_attrs = attrs(&[(attribute, PostureValue::String(actual.into()))]);
        assert_eq!(assertion.evaluate(&device_attrs), expected);
    }

    #[test]
    fn evaluate_is_set_and_not_set() {
        let is_set = parse_assertion("device:antivirusName IS SET").unwrap();
        let not_set = parse_assertion("device:antivirusName IS NOT SET").unwrap();

        let with = attrs(&[(
            "device:antivirusName",
            PostureValue::String("Defender".into()),
        )]);
        let without: HashMap<String, PostureValue> = HashMap::new();

        assert!(is_set.evaluate(&with));
        assert!(!is_set.evaluate(&without));
        assert!(!not_set.evaluate(&with));
        assert!(not_set.evaluate(&without));
    }

    #[test]
    fn evaluate_posture_and_logic() {
        let assertions = parse_assertions(&[
            "device:diskEncryption == true",
            "device:firewallEnabled == true",
        ])
        .unwrap();
        let attrs = attrs(&[
            ("device:diskEncryption", PostureValue::Bool(true)),
            ("device:firewallEnabled", PostureValue::Bool(false)),
        ]);
        let result = evaluate_posture(&assertions, &attrs);
        assert!(!result.passed);
        assert_eq!(result.failing_assertions.len(), 1);
    }

    #[test]
    fn evaluate_named_postures_or_logic() {
        let mut postures = HashMap::new();
        postures.insert(
            "posture:a".into(),
            parse_assertions(&["device:diskEncryption == true"]).unwrap(),
        );
        postures.insert(
            "posture:b".into(),
            parse_assertions(&["device:firewallEnabled == true"]).unwrap(),
        );

        let attrs = attrs(&[
            ("device:diskEncryption", PostureValue::Bool(true)),
            ("device:firewallEnabled", PostureValue::Bool(false)),
        ]);

        let summary =
            evaluate_named_postures(&postures, &["posture:a".into(), "posture:b".into()], &attrs);
        assert!(summary.passed);
        assert!(summary.results["posture:a"].passed);
        assert!(!summary.results["posture:b"].passed);
    }

    #[test]
    fn evaluate_file_exists_function_key() {
        let assertion = parse_assertion("device:fileExists('/etc/x') == true").unwrap();
        let attrs = attrs(&[("device:fileExists:/etc/x", PostureValue::Bool(true))]);
        assert!(assertion.evaluate(&attrs));
    }
}
