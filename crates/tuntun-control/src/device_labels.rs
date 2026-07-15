use std::collections::HashMap;

use serde_json::{Map, Value};

pub fn normalize_labels(value: &Value) -> HashMap<String, String> {
    let Some(obj) = value.as_object() else {
        return HashMap::new();
    };
    obj.iter()
        .filter_map(|(k, v)| {
            let s = v.as_str()?;
            if k.is_empty() || s.is_empty() {
                return None;
            }
            Some((k.clone(), s.to_string()))
        })
        .collect()
}

pub fn merge_labels(
    existing: &HashMap<String, String>,
    patch: &HashMap<String, Option<String>>,
) -> HashMap<String, String> {
    let mut next = existing.clone();
    for (key, value) in patch {
        match value {
            None => {
                next.remove(key);
            }
            Some(s) if s.is_empty() => {
                next.remove(key);
            }
            Some(s) => {
                next.insert(key.clone(), s.clone());
            }
        }
    }
    next
}

pub fn labels_to_json(labels: &HashMap<String, String>) -> Value {
    let mut map = Map::new();
    for (k, v) in labels {
        map.insert(k.clone(), Value::String(v.clone()));
    }
    Value::Object(map)
}
