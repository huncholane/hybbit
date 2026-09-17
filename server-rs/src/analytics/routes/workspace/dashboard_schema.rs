//! Port of server/src/api/analytics/dashboards/dashboardSchema.ts. The parsed
//! config is what Node stores (`JSON.stringify` of zod's output, unknown keys
//! stripped), so it is rebuilt here as the same JavaScript object.

use super::schema::{self, Field, ObjectStatus, StringCheck};
use crate::analytics::js::{
    JsObject, JsValue,
    zod::{self, Parsed, Path, ZodIssue},
};

/// `MAX_CARDS_PER_DASHBOARD`
pub const MAX_CARDS_PER_DASHBOARD: usize = 20;

const VIZ_TYPES: [&str; 9] = ["table", "line", "area", "bar", "hbar", "pie", "stat", "map", "calendar"];
const VALUE_FORMATS: [&str; 4] = ["number", "percent", "duration", "bytes"];

/// Builds zod's output object: shape keys in order, absent optional keys left out.
struct Output(JsObject);

impl Output {
    fn new() -> Self {
        Self(JsObject::new())
    }

    fn set(&mut self, name: &str, value: Option<JsValue>) {
        if let Some(value) = value {
            self.0.insert(name, value);
        }
    }

    fn set_optional(&mut self, name: &str, value: Option<Field<JsValue>>) {
        if let Some(Field::Value(value)) = value {
            self.0.insert(name, value);
        }
    }
}

fn plain_string(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<JsValue> {
    schema::string(value, path, issues, &[]).map(|(status, text)| (status, JsValue::String(text)))
}

fn optional_string(object: &JsObject, name: &str, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<Field<JsValue>> {
    schema::optional(object.get_or_undefined(name), |inner| plain_string(inner, &schema::key(path, name), issues))
}

/// `gridPosSchema`
fn grid_pos(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<JsValue> {
    let object = schema::object(value, path, issues)?;
    let mut status = ObjectStatus::new();
    let mut output = Output::new();
    for name in ["x", "y", "w", "h"] {
        let parsed = schema::number(object.get_or_undefined(name), &schema::key(path, name), issues, false, false);
        output.set(name, status.field(parsed).map(JsValue::Number));
    }
    status.finish().map(|object_status| (object_status, JsValue::Object(output.0)))
}

/// `cardMappingSchema`
fn mapping(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<JsValue> {
    let object = schema::object(value, path, issues)?;
    let mut status = ObjectStatus::new();
    let mut output = Output::new();
    let x_column = status.field(optional_string(object, "xColumn", path, issues));
    output.set_optional("xColumn", x_column);
    let y_columns = status.field(schema::optional(object.get_or_undefined("yColumns"), |inner| {
        schema::array(inner, &schema::key(path, "yColumns"), issues, None, plain_string)
            .map(|(array_status, items)| (array_status, JsValue::Array(items)))
    }));
    output.set_optional("yColumns", y_columns);
    for name in ["seriesColumn", "valueColumn"] {
        let parsed = status.field(optional_string(object, name, path, issues));
        output.set_optional(name, parsed);
    }
    let value_format = status.field(schema::optional(object.get_or_undefined("valueFormat"), |inner| {
        zod::enumeration(inner, &VALUE_FORMATS, &schema::key(path, "valueFormat"), issues)
            .map(|(field_status, text)| (field_status, JsValue::String(text)))
    }));
    output.set_optional("valueFormat", value_format);
    for name in ["countryColumn", "dateColumn"] {
        let parsed = status.field(optional_string(object, name, path, issues));
        output.set_optional(name, parsed);
    }
    status.finish().map(|object_status| (object_status, JsValue::Object(output.0)))
}

/// `cardSchema`
fn card(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<JsValue> {
    let object = schema::object(value, path, issues)?;
    let mut status = ObjectStatus::new();
    let mut output = Output::new();
    let id = schema::string(object.get_or_undefined("id"), &schema::key(path, "id"), issues, &[StringCheck::Min(1, None)]);
    output.set("id", status.field(id).map(JsValue::String));
    for name in ["title", "sql"] {
        let parsed = plain_string(object.get_or_undefined(name), &schema::key(path, name), issues);
        output.set(name, status.field(parsed));
    }
    let viz_type = zod::enumeration(object.get_or_undefined("vizType"), &VIZ_TYPES, &schema::key(path, "vizType"), issues);
    output.set("vizType", status.field(viz_type).map(JsValue::String));
    let parsed_mapping = mapping(object.get_or_undefined("mapping"), &schema::key(path, "mapping"), issues);
    output.set("mapping", status.field(parsed_mapping));
    let parsed_grid = grid_pos(object.get_or_undefined("gridPos"), &schema::key(path, "gridPos"), issues);
    output.set("gridPos", status.field(parsed_grid));
    status.finish().map(|object_status| (object_status, JsValue::Object(output.0)))
}

/// `dashboardConfigSchema`
fn config(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<JsValue> {
    let object = schema::object(value, path, issues)?;
    let mut status = ObjectStatus::new();
    let message = format!("A dashboard can have at most {MAX_CARDS_PER_DASHBOARD} cards");
    let cards = schema::array(
        object.get_or_undefined("cards"),
        &schema::key(path, "cards"),
        issues,
        Some((MAX_CARDS_PER_DASHBOARD, Some(&message))),
        card,
    );
    let mut output = Output::new();
    output.set("cards", status.field(cards).map(JsValue::Array));
    status.finish().map(|object_status| (object_status, JsValue::Object(output.0)))
}

/// A parsed create or update body.
#[derive(Clone, Debug, PartialEq)]
pub struct DashboardBody {
    pub name: Option<String>,
    /// zod's output for `config`, ready for `JSON.stringify`
    pub config: Option<JsValue>,
}

fn parse(body: &JsValue, create: bool) -> Result<DashboardBody, Vec<ZodIssue>> {
    let root: Path = Vec::new();
    let mut issues = Vec::new();
    let Some(object) = schema::object(body, &root, &mut issues) else { return Err(issues) };
    let mut status = ObjectStatus::new();
    let name_path = schema::key(&root, "name");
    let name = if create {
        status
            .field(schema::string(
                object.get_or_undefined("name"),
                &name_path,
                &mut issues,
                &[StringCheck::Min(1, Some("Dashboard name is required"))],
            ))
            .map(Field::Value)
    } else {
        status.field(schema::optional(object.get_or_undefined("name"), |inner| {
            schema::string(inner, &name_path, &mut issues, &[StringCheck::Min(1, None)])
        }))
    };
    let parsed_config = status.field(schema::optional(object.get_or_undefined("config"), |inner| {
        config(inner, &schema::key(&root, "config"), &mut issues)
    }));
    let object_status = status.finish();
    let (Some(name), Some(parsed_config), Some(object_status)) = (name, parsed_config, object_status) else {
        return Err(issues);
    };
    let name = match name {
        Field::Value(text) => Some(text),
        _ => None,
    };
    let config = match parsed_config {
        Field::Value(value) => Some(value),
        _ => None,
    };
    schema::finish(Some((object_status, DashboardBody { name, config })), issues)
}

/// `createDashboardSchema.parse(body)`
pub fn parse_create(body: &JsValue) -> Result<DashboardBody, Vec<ZodIssue>> {
    parse(body, true)
}

/// `updateDashboardSchema.parse(body)`
pub fn parse_update(body: &JsValue) -> Result<DashboardBody, Vec<ZodIssue>> {
    parse(body, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::js::json;

    fn parse_text(text: &str) -> Result<DashboardBody, Vec<ZodIssue>> {
        parse_create(&json::parse(text).unwrap())
    }

    #[test]
    fn strips_unknown_keys_in_schema_order() {
        let parsed = parse_text(
            r#"{"name":"d","config":{"cards":[{"zzz":1,"gridPos":{"h":2,"w":0.1,"x":0,"y":1e21},"id":"c1","title":"t","sql":"select 1","vizType":"table","mapping":{"extra":1,"yColumns":["a"]}}],"other":true}}"#,
        )
        .unwrap();
        assert_eq!(
            json::stringify(&parsed.config.unwrap()).unwrap(),
            r#"{"cards":[{"id":"c1","title":"t","sql":"select 1","vizType":"table","mapping":{"yColumns":["a"]},"gridPos":{"x":0,"y":1e+21,"w":0.1,"h":2}}]}"#
        );
    }

    #[test]
    fn reports_zod_issues() {
        let issues = parse_text(r#"{"name":"","config":{"cards":[{"id":"","vizType":"donut","mapping":null,"gridPos":{"x":"1"}}]}}"#)
            .unwrap_err();
        assert_eq!(
            json::stringify(&zod::issues_value(&issues)).unwrap(),
            concat!(
                r#"[{"code":"too_small","minimum":1,"type":"string","inclusive":true,"exact":false,"message":"Dashboard name is required","path":["name"]},"#,
                r#"{"code":"too_small","minimum":1,"type":"string","inclusive":true,"exact":false,"message":"String must contain at least 1 character(s)","path":["config","cards",0,"id"]},"#,
                r#"{"code":"invalid_type","expected":"string","received":"undefined","path":["config","cards",0,"title"],"message":"Required"},"#,
                r#"{"code":"invalid_type","expected":"string","received":"undefined","path":["config","cards",0,"sql"],"message":"Required"},"#,
                r#"{"received":"donut","code":"invalid_enum_value","options":["table","line","area","bar","hbar","pie","stat","map","calendar"],"path":["config","cards",0,"vizType"],"message":"Invalid enum value. Expected 'table' | 'line' | 'area' | 'bar' | 'hbar' | 'pie' | 'stat' | 'map' | 'calendar', received 'donut'"},"#,
                r#"{"code":"invalid_type","expected":"object","received":"null","path":["config","cards",0,"mapping"],"message":"Expected object, received null"},"#,
                r#"{"code":"invalid_type","expected":"number","received":"string","path":["config","cards",0,"gridPos","x"],"message":"Expected number, received string"},"#,
                r#"{"code":"invalid_type","expected":"number","received":"undefined","path":["config","cards",0,"gridPos","y"],"message":"Required"},"#,
                r#"{"code":"invalid_type","expected":"number","received":"undefined","path":["config","cards",0,"gridPos","w"],"message":"Required"},"#,
                r#"{"code":"invalid_type","expected":"number","received":"undefined","path":["config","cards",0,"gridPos","h"],"message":"Required"}]"#
            )
        );
    }
}
