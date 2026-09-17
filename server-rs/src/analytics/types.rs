//! Shared analytics types: server/src/api/analytics/types.ts and the pieces of
//! `@hygo/shared` it re-exports (`shared/src/filters.ts`, `time.ts`,
//! `performance.ts`).

use std::fmt;

use super::js::{JsObject, JsValue};

/// `FilterType`, in the order `filterTypeSchema` lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FilterType {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    StartsWith,
    EndsWith,
    Regex,
    NotRegex,
    IsNull,
    IsNotNull,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
}

impl FilterType {
    pub const ALL: [FilterType; 14] = [
        FilterType::Equals,
        FilterType::NotEquals,
        FilterType::Contains,
        FilterType::NotContains,
        FilterType::StartsWith,
        FilterType::EndsWith,
        FilterType::Regex,
        FilterType::NotRegex,
        FilterType::IsNull,
        FilterType::IsNotNull,
        FilterType::GreaterThan,
        FilterType::LessThan,
        FilterType::GreaterThanOrEqual,
        FilterType::LessThanOrEqual,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            FilterType::Equals => "equals",
            FilterType::NotEquals => "not_equals",
            FilterType::Contains => "contains",
            FilterType::NotContains => "not_contains",
            FilterType::StartsWith => "starts_with",
            FilterType::EndsWith => "ends_with",
            FilterType::Regex => "regex",
            FilterType::NotRegex => "not_regex",
            FilterType::IsNull => "is_null",
            FilterType::IsNotNull => "is_not_null",
            FilterType::GreaterThan => "greater_than",
            FilterType::LessThan => "less_than",
            FilterType::GreaterThanOrEqual => "greater_than_or_equal",
            FilterType::LessThanOrEqual => "less_than_or_equal",
        }
    }

    pub fn parse(text: &str) -> Option<FilterType> {
        FilterType::ALL.into_iter().find(|kind| kind.as_str() == text)
    }

    pub fn names() -> [&'static str; 14] {
        FilterType::ALL.map(FilterType::as_str)
    }
}

impl fmt::Display for FilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `FilterParameter`: the fixed dimensions plus `feature_flag:<key>`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FilterParameter {
    Browser,
    OperatingSystem,
    Language,
    Country,
    Region,
    City,
    DeviceType,
    Referrer,
    Hostname,
    Pathname,
    PageTitle,
    Querystring,
    EventName,
    Channel,
    UtmSource,
    UtmMedium,
    UtmCampaign,
    UtmTerm,
    UtmContent,
    EntryPage,
    ExitPage,
    Dimensions,
    BrowserVersion,
    OperatingSystemVersion,
    UserId,
    Lat,
    Lon,
    Timezone,
    Tag,
    /// The key after `feature_flag:`
    FeatureFlag(String),
}

impl FilterParameter {
    /// `baseFilterParamSchema` in declaration order (zod lists them in errors).
    pub const BASE: [FilterParameter; 29] = [
        FilterParameter::Browser,
        FilterParameter::OperatingSystem,
        FilterParameter::Language,
        FilterParameter::Country,
        FilterParameter::Region,
        FilterParameter::City,
        FilterParameter::DeviceType,
        FilterParameter::Referrer,
        FilterParameter::Hostname,
        FilterParameter::Pathname,
        FilterParameter::PageTitle,
        FilterParameter::Querystring,
        FilterParameter::EventName,
        FilterParameter::Channel,
        FilterParameter::UtmSource,
        FilterParameter::UtmMedium,
        FilterParameter::UtmCampaign,
        FilterParameter::UtmTerm,
        FilterParameter::UtmContent,
        FilterParameter::EntryPage,
        FilterParameter::ExitPage,
        FilterParameter::Dimensions,
        FilterParameter::BrowserVersion,
        FilterParameter::OperatingSystemVersion,
        FilterParameter::UserId,
        FilterParameter::Lat,
        FilterParameter::Lon,
        FilterParameter::Timezone,
        FilterParameter::Tag,
    ];

    pub fn base_name(&self) -> Option<&'static str> {
        Some(match self {
            FilterParameter::Browser => "browser",
            FilterParameter::OperatingSystem => "operating_system",
            FilterParameter::Language => "language",
            FilterParameter::Country => "country",
            FilterParameter::Region => "region",
            FilterParameter::City => "city",
            FilterParameter::DeviceType => "device_type",
            FilterParameter::Referrer => "referrer",
            FilterParameter::Hostname => "hostname",
            FilterParameter::Pathname => "pathname",
            FilterParameter::PageTitle => "page_title",
            FilterParameter::Querystring => "querystring",
            FilterParameter::EventName => "event_name",
            FilterParameter::Channel => "channel",
            FilterParameter::UtmSource => "utm_source",
            FilterParameter::UtmMedium => "utm_medium",
            FilterParameter::UtmCampaign => "utm_campaign",
            FilterParameter::UtmTerm => "utm_term",
            FilterParameter::UtmContent => "utm_content",
            FilterParameter::EntryPage => "entry_page",
            FilterParameter::ExitPage => "exit_page",
            FilterParameter::Dimensions => "dimensions",
            FilterParameter::BrowserVersion => "browser_version",
            FilterParameter::OperatingSystemVersion => "operating_system_version",
            FilterParameter::UserId => "user_id",
            FilterParameter::Lat => "lat",
            FilterParameter::Lon => "lon",
            FilterParameter::Timezone => "timezone",
            FilterParameter::Tag => "tag",
            FilterParameter::FeatureFlag(_) => return None,
        })
    }

    pub fn base_names() -> [&'static str; 29] {
        FilterParameter::BASE.map(|parameter| parameter.base_name().expect("base parameter"))
    }

    /// The parameter's wire spelling.
    pub fn as_string(&self) -> String {
        match self {
            FilterParameter::FeatureFlag(key) => format!("feature_flag:{key}"),
            base => base.base_name().expect("base parameter").to_string(),
        }
    }

    /// A fixed dimension by name, or `feature_flag:<anything>` (unvalidated).
    pub fn from_name(name: &str) -> Option<FilterParameter> {
        if let Some(key) = name.strip_prefix("feature_flag:") {
            return Some(FilterParameter::FeatureFlag(key.to_string()));
        }
        FilterParameter::BASE.into_iter().find(|parameter| parameter.base_name() == Some(name))
    }
}

impl fmt::Display for FilterParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_string())
    }
}

/// One entry of `Filter.value`: `z.string().or(z.number())`.
#[derive(Clone, Debug, PartialEq)]
pub enum FilterValue {
    String(String),
    Number(f64),
}

impl FilterValue {
    pub fn to_js(&self) -> JsValue {
        match self {
            FilterValue::String(text) => JsValue::String(text.clone()),
            FilterValue::Number(number) => JsValue::Number(*number),
        }
    }

    /// `String(value)`.
    pub fn to_js_string(&self) -> String {
        self.to_js().to_js_string()
    }

    /// `Number(value)`.
    pub fn to_number(&self) -> f64 {
        self.to_js().to_number()
    }
}

/// `Filter` as validated by `filterSchema`.
#[derive(Clone, Debug, PartialEq)]
pub struct Filter {
    pub parameter: FilterParameter,
    pub filter_type: FilterType,
    pub value: Vec<FilterValue>,
}

impl Filter {
    /// The object zod returns: `{ parameter, type, value }` in schema order.
    pub fn to_js(&self) -> JsValue {
        let mut object = JsObject::new();
        object.insert("parameter", JsValue::String(self.parameter.as_string()));
        object.insert("type", JsValue::String(self.filter_type.as_str().to_string()));
        object.insert("value", JsValue::Array(self.value.iter().map(FilterValue::to_js).collect()));
        JsValue::Object(object)
    }
}

/// `TimeBucket`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimeBucket {
    Minute,
    FiveMinutes,
    TenMinutes,
    FifteenMinutes,
    Hour,
    Day,
    Week,
    Month,
    Year,
}

impl TimeBucket {
    pub const ALL: [TimeBucket; 9] = [
        TimeBucket::Minute,
        TimeBucket::FiveMinutes,
        TimeBucket::TenMinutes,
        TimeBucket::FifteenMinutes,
        TimeBucket::Hour,
        TimeBucket::Day,
        TimeBucket::Week,
        TimeBucket::Month,
        TimeBucket::Year,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            TimeBucket::Minute => "minute",
            TimeBucket::FiveMinutes => "five_minutes",
            TimeBucket::TenMinutes => "ten_minutes",
            TimeBucket::FifteenMinutes => "fifteen_minutes",
            TimeBucket::Hour => "hour",
            TimeBucket::Day => "day",
            TimeBucket::Week => "week",
            TimeBucket::Month => "month",
            TimeBucket::Year => "year",
        }
    }

    pub fn parse(text: &str) -> Option<TimeBucket> {
        TimeBucket::ALL.into_iter().find(|bucket| bucket.as_str() == text)
    }
}

/// `WebVitalMetric`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WebVitalMetric {
    Lcp,
    Cls,
    Inp,
    Fcp,
    Ttfb,
}

impl WebVitalMetric {
    pub const ALL: [WebVitalMetric; 5] =
        [WebVitalMetric::Lcp, WebVitalMetric::Cls, WebVitalMetric::Inp, WebVitalMetric::Fcp, WebVitalMetric::Ttfb];

    pub fn as_str(self) -> &'static str {
        match self {
            WebVitalMetric::Lcp => "lcp",
            WebVitalMetric::Cls => "cls",
            WebVitalMetric::Inp => "inp",
            WebVitalMetric::Fcp => "fcp",
            WebVitalMetric::Ttfb => "ttfb",
        }
    }
}

/// `PercentileLevel`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PercentileLevel {
    P50,
    P75,
    P90,
    P99,
}

impl PercentileLevel {
    pub const ALL: [PercentileLevel; 4] =
        [PercentileLevel::P50, PercentileLevel::P75, PercentileLevel::P90, PercentileLevel::P99];

    pub fn as_str(self) -> &'static str {
        match self {
            PercentileLevel::P50 => "p50",
            PercentileLevel::P75 => "p75",
            PercentileLevel::P90 => "p90",
            PercentileLevel::P99 => "p99",
        }
    }
}

/// The `${metric}_${percentile}` column names of `PerformanceOverviewMetrics`,
/// in the order the mapped types enumerate them.
pub fn performance_metric_columns() -> Vec<String> {
    WebVitalMetric::ALL
        .iter()
        .flat_map(|metric| PercentileLevel::ALL.iter().map(move |level| format!("{}_{}", metric.as_str(), level.as_str())))
        .collect()
}
