//! OpenTelemetry export: usage metrics and events, when the operator asks.
//!
//! Off unless `ORBIT_ENABLE_TELEMETRY=1` (or Claude Code's
//! `CLAUDE_CODE_ENABLE_TELEMETRY=1` with `claude_compat` on) **and** an
//! endpoint is named with the standard variables:
//!
//! * `OTEL_EXPORTER_OTLP_ENDPOINT` (`/v1/metrics` and `/v1/logs` are added),
//!   or `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` /
//!   `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` for either signal on its own;
//! * `OTEL_EXPORTER_OTLP_HEADERS` (`name=value,name=value`);
//! * `OTEL_EXPORTER_OTLP_PROTOCOL`: `http/json` (also when unset),
//!   `http/protobuf` or `grpc`. Any other value exports nothing.
//!   `OTEL_EXPORTER_OTLP_METRICS_PROTOCOL` and
//!   `OTEL_EXPORTER_OTLP_LOGS_PROTOCOL` choose it for one signal; a value
//!   that is not one of the three stops that signal. With `grpc` the endpoint
//!   is the collector's address (`http://host:4317`); the service path is
//!   added, also to a signal's own endpoint.
//!
//! What is sent, after each turn and at most once a batch:
//!
//! * metrics `orbit.session.count`, `orbit.token.usage` (attribute `type`:
//!   `input`, `output`, `cacheRead`, `cacheCreation`), `orbit.cost.usage`
//!   (USD);
//! * events `orbit.api_request` (one per turn: model, provider, tokens,
//!   cost, rounds, whether it succeeded) and `orbit.tool_result` (tool
//!   name, whether it succeeded, how long it took).
//!
//! * traces, only when `OTEL_TRACES_EXPORTER=otlp` (the standard
//!   variable; Claude Code's traces are opt-in too): one trace per turn,
//!   with a root span `orbit.turn` (the attributes of `orbit.api_request`)
//!   and a child span `orbit.tool` for each tool call (tool name, whether
//!   it succeeded). They go to `<endpoint>/v1/traces`, or
//!   `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, in the form
//!   `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` or the general variable names.
//!
//! Never sent: prompts, replies, tool arguments or results, file paths.
//! Every record carries `session.id`; the resource is `service.name =
//! orbit` with the version. One `curl` POST per signal, five seconds at
//! most, off the session's thread; a failed export is dropped, and with
//! `grpc` the collector's status is not read.
//!
//! The protobuf form is written here, field by field, from the published
//! OTLP messages (`opentelemetry-proto`: `ExportMetricsServiceRequest`,
//! `ExportLogsServiceRequest`); it carries exactly what the JSON form does.

use std::path::Path;
use std::sync::Mutex;

const MAX_PENDING: usize = 512;

/// Where and how to export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exporter {
    pub metrics_url: Option<String>,
    pub logs_url: Option<String>,
    pub headers: Vec<(String, String)>,
    /// How each signal is spoken: its own protocol variable, else the
    /// general one, else `http/json`.
    pub metrics_protocol: Protocol,
    pub logs_protocol: Protocol,
    /// Where spans go; `None` unless `OTEL_TRACES_EXPORTER=otlp`.
    pub traces_url: Option<String>,
    pub traces_protocol: Protocol,
}

/// How a batch is written and sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// OTLP/HTTP with a JSON body.
    HttpJson,
    /// OTLP/HTTP with a protobuf body.
    HttpProtobuf,
    /// OTLP/gRPC: the protobuf message in one gRPC frame, over HTTP/2.
    Grpc,
}

const GRPC_METRICS_PATH: &str = "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export";
const GRPC_LOGS_PATH: &str = "/opentelemetry.proto.collector.logs.v1.LogsService/Export";
const GRPC_TRACES_PATH: &str = "/opentelemetry.proto.collector.trace.v1.TraceService/Export";

fn url_ok(url: &str) -> bool {
    (url.starts_with("https://") || url.starts_with("http://"))
        && !url.contains(char::is_whitespace)
        && !url.chars().any(char::is_control)
}

/// The exporter the environment describes, read through `var` (the
/// process's environment in use, a table in tests). `None` when telemetry
/// is off, no endpoint is named, or a protocol ORBIT does not speak is.
pub fn exporter_from(
    var: &dyn Fn(&str) -> Option<String>,
    claude_compat: bool,
) -> Option<Exporter> {
    let on = |name: &str| var(name).is_some_and(|value| matches!(value.trim(), "1" | "true"));
    if !(on("ORBIT_ENABLE_TELEMETRY") || (claude_compat && on("CLAUDE_CODE_ENABLE_TELEMETRY"))) {
        return None;
    }
    // `Ok(None)`: not named. `Err`: named, and not a protocol spoken here.
    let named = |name: &str| match var(name).unwrap_or_default().trim() {
        "" => Ok(None),
        "http/json" => Ok(Some(Protocol::HttpJson)),
        "http/protobuf" => Ok(Some(Protocol::HttpProtobuf)),
        "grpc" => Ok(Some(Protocol::Grpc)),
        _ => Err(()),
    };
    let general = named("OTEL_EXPORTER_OTLP_PROTOCOL").ok()?;
    let base = var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .map(|url| url.trim().trim_end_matches('/').to_owned())
        .filter(|url| url_ok(url));
    // A signal's protocol and where it goes; `None` when it has nowhere to
    // go or names a protocol that is not spoken.
    let signal = |protocol: &str, own: &str, path: &str, service: &str| {
        let protocol = named(protocol)
            .ok()?
            .or(general)
            .unwrap_or(Protocol::HttpJson);
        let own = var(own)
            .map(|url| url.trim().to_owned())
            .filter(|url| url_ok(url));
        let url = if protocol == Protocol::Grpc {
            // A gRPC endpoint is an address; the call's path is fixed.
            own.as_ref()
                .or(base.as_ref())
                .map(|address| format!("{}{service}", address.trim_end_matches('/')))
        } else {
            own.or_else(|| base.as_ref().map(|base| format!("{base}{path}")))
        };
        Some((url?, protocol))
    };
    let metrics = signal(
        "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL",
        "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
        "/v1/metrics",
        GRPC_METRICS_PATH,
    );
    let logs = signal(
        "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
        "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
        "/v1/logs",
        GRPC_LOGS_PATH,
    );
    let protocol_of = |signal: &Option<(String, Protocol)>| {
        signal
            .as_ref()
            .map_or(Protocol::HttpJson, |(_, protocol)| *protocol)
    };
    // Spans are a separate choice, made with the standard variable.
    let traces = var("OTEL_TRACES_EXPORTER")
        .is_some_and(|value| value.trim() == "otlp")
        .then(|| {
            signal(
                "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                "/v1/traces",
                GRPC_TRACES_PATH,
            )
        })
        .flatten();
    let exporter = Exporter {
        traces_protocol: protocol_of(&traces),
        traces_url: traces.map(|(url, _)| url),
        metrics_protocol: protocol_of(&metrics),
        logs_protocol: protocol_of(&logs),
        metrics_url: metrics.map(|(url, _)| url),
        logs_url: logs.map(|(url, _)| url),
        headers: var("OTEL_EXPORTER_OTLP_HEADERS")
            .unwrap_or_default()
            .split(',')
            .filter_map(|pair| pair.split_once('='))
            .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
            .filter(|(name, value)| {
                !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
                    && !value.chars().any(char::is_control)
            })
            .take(16)
            .collect(),
    };
    (exporter.metrics_url.is_some() || exporter.logs_url.is_some() || exporter.traces_url.is_some())
        .then_some(exporter)
}

fn exporter(home: &Path) -> Option<Exporter> {
    exporter_from(
        &|name| std::env::var(name).ok(),
        orbit_engine::hooks::claude_compat(home),
    )
}

/// One measurement or event waiting to be sent.
#[derive(Debug, Clone, PartialEq)]
enum Record {
    /// A counter increment: name, unit, value, attributes.
    Sum(&'static str, &'static str, f64, Vec<(&'static str, String)>),
    /// An event: name and attributes.
    Event(&'static str, Vec<(&'static str, String)>),
    /// A finished span of a turn's trace.
    Span(Span),
}

/// One span: a turn (no parent) or a tool call inside it.
#[derive(Debug, Clone, PartialEq)]
struct Span {
    name: &'static str,
    trace_id: [u8; 16],
    span_id: [u8; 8],
    parent: Option<[u8; 8]>,
    start: u128,
    end: u128,
    ok: bool,
    attributes: Vec<(&'static str, String)>,
}

/// A turn's trace: its id, its root span's id and when it began.
type TraceContext = ([u8; 16], [u8; 8], u128);

/// The trace of the turn that is running.
static TRACE: Mutex<Option<TraceContext>> = Mutex::new(None);

fn random_id<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut id = [0_u8; N];
    // An id of all zeros is not valid; the odds are not worth a loop, the
    // last byte is simply never zero.
    rand::rngs::OsRng.fill_bytes(&mut id);
    id[N - 1] |= 1;
    id
}

/// The running turn's trace, begun now when there is none.
fn trace() -> TraceContext {
    let mut current = TRACE.lock().unwrap_or_else(|lock| lock.into_inner());
    *current.get_or_insert_with(|| (random_id(), random_id(), now_nanos()))
}

/// A turn begins: its tool calls and its own span share one trace from
/// here. Does nothing unless spans are exported.
pub fn turn_started(home: &Path) {
    if exporter(home).is_none_or(|exporter| exporter.traces_url.is_none()) {
        return;
    }
    let mut current = TRACE.lock().unwrap_or_else(|lock| lock.into_inner());
    *current = Some((random_id(), random_id(), now_nanos()));
}

/// The turn's own span, closing its trace. `None` unless spans are exported.
fn turn_span(home: &Path, turn: &Turn) -> Option<Record> {
    exporter(home)?.traces_url?;
    let (trace_id, span_id, start) = trace();
    *TRACE.lock().unwrap_or_else(|lock| lock.into_inner()) = None;
    let attributes = match turn_records(turn).pop() {
        Some(Record::Event(_, attributes)) => attributes,
        _ => Vec::new(),
    };
    Some(Record::Span(Span {
        name: "orbit.turn",
        trace_id,
        span_id,
        parent: None,
        start,
        end: now_nanos().max(start),
        ok: turn.ok,
        attributes,
    }))
}

static PENDING: Mutex<Vec<(u128, Record)>> = Mutex::new(Vec::new());

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos())
}

fn push(record: Record) {
    if let Ok(mut pending) = PENDING.lock()
        && pending.len() < MAX_PENDING
    {
        pending.push((now_nanos(), record));
    }
}

/// A session opened in this process.
pub fn session_started(home: &Path, session_id: &str) {
    if exporter(home).is_none() {
        return;
    }
    push(Record::Sum(
        "orbit.session.count",
        "count",
        1.0,
        vec![("session.id", session_id.to_owned())],
    ));
}

/// What one finished turn used.
#[derive(Debug, Clone, Default)]
pub struct Turn {
    pub session_id: String,
    pub model: String,
    pub provider: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub cost_microdollars: u64,
    pub rounds: u32,
    pub ok: bool,
}

impl Turn {
    /// The turn's numbers from the engine's report. Cache counts come from
    /// the request receipts whose usage the provider reported.
    pub fn from_report(
        session_id: &str,
        model: &str,
        provider: &str,
        report: &orbit_engine::TurnReport,
    ) -> Self {
        let usages = || {
            report
                .attempts
                .iter()
                .filter(|receipt| receipt.knownness == orbit_engine::AccountingKnownness::Known)
                .filter_map(|receipt| receipt.usage)
        };
        Turn {
            session_id: session_id.to_owned(),
            model: model.to_owned(),
            provider: provider.to_owned(),
            input_tokens: report.input_tokens,
            output_tokens: report.output_tokens,
            cache_read_tokens: usages().map(|usage| usage.cache_read_tokens).sum(),
            cache_write_tokens: usages().map(|usage| usage.cache_write_tokens).sum(),
            // The report's field is named for micro-cents and holds
            // micro-dollars (see HANDOFF).
            cost_microdollars: report.cost_microcents,
            rounds: report.rounds,
            ok: report.ok,
        }
    }
}

fn turn_records(turn: &Turn) -> Vec<Record> {
    let common = |extra: Vec<(&'static str, String)>| {
        let mut attributes = vec![
            ("session.id", turn.session_id.clone()),
            ("model", turn.model.clone()),
        ];
        attributes.extend(extra);
        attributes
    };
    let mut records = Vec::new();
    for (kind, tokens) in [
        ("input", turn.input_tokens),
        ("output", turn.output_tokens),
        ("cacheRead", turn.cache_read_tokens),
        ("cacheCreation", turn.cache_write_tokens),
    ] {
        if tokens > 0 {
            records.push(Record::Sum(
                "orbit.token.usage",
                "tokens",
                tokens as f64,
                common(vec![("type", kind.to_owned())]),
            ));
        }
    }
    let usd = turn.cost_microdollars as f64 / 1_000_000.0;
    if turn.cost_microdollars > 0 {
        records.push(Record::Sum(
            "orbit.cost.usage",
            "USD",
            usd,
            common(Vec::new()),
        ));
    }
    records.push(Record::Event(
        "orbit.api_request",
        common(vec![
            ("provider", turn.provider.clone()),
            ("input_tokens", turn.input_tokens.to_string()),
            ("output_tokens", turn.output_tokens.to_string()),
            ("cache_read_tokens", turn.cache_read_tokens.to_string()),
            ("cache_creation_tokens", turn.cache_write_tokens.to_string()),
            ("cost_usd", format!("{usd:.6}")),
            ("rounds", turn.rounds.to_string()),
            ("success", turn.ok.to_string()),
        ]),
    ));
    records
}

/// A turn finished: record what it used and send what is waiting, off
/// this thread. For a session that goes on.
pub fn turn_finished(home: &Path, turn: &Turn) {
    let Some(exporter) = exporter(home) else {
        return;
    };
    for record in turn_records(turn).into_iter().chain(turn_span(home, turn)) {
        push(record);
    }
    flush(&exporter);
}

/// Record a finished turn without sending yet: a run that is about to end
/// sends everything at once with [`finish`], on its own thread, so the
/// process does not exit under an export.
pub fn turn_recorded(home: &Path, turn: &Turn) {
    if exporter(home).is_none() {
        return;
    }
    for record in turn_records(turn).into_iter().chain(turn_span(home, turn)) {
        push(record);
    }
}

/// A tool call finished. Its name, outcome and duration only.
pub fn tool_result(
    home: &Path,
    session_id: &str,
    tool: &str,
    ok: bool,
    elapsed: std::time::Duration,
) {
    let Some(exporter) = exporter(home) else {
        return;
    };
    // An MCP tool's wire name can carry a server name the operator chose;
    // it is still a name, not content. Bounded, printable.
    let tool: String = tool.chars().filter(|c| !c.is_control()).take(128).collect();
    if exporter.traces_url.is_some() {
        let (trace_id, parent, _) = trace();
        let end = now_nanos();
        push(Record::Span(Span {
            name: "orbit.tool",
            trace_id,
            span_id: random_id(),
            parent: Some(parent),
            start: end.saturating_sub(elapsed.as_nanos()),
            end,
            ok,
            attributes: vec![
                ("session.id", session_id.to_owned()),
                ("tool_name", tool.clone()),
            ],
        }));
    }
    push(Record::Event(
        "orbit.tool_result",
        vec![
            ("session.id", session_id.to_owned()),
            ("tool_name", tool),
            ("success", ok.to_string()),
            ("duration_ms", elapsed.as_millis().to_string()),
        ],
    ));
}

fn attributes(list: &[(&'static str, String)]) -> serde_json::Value {
    list.iter()
        .map(|(key, value)| serde_json::json!({"key": key, "value": {"stringValue": value}}))
        .collect()
}

fn resource() -> serde_json::Value {
    serde_json::json!({"attributes": [
        {"key": "service.name", "value": {"stringValue": "orbit"}},
        {"key": "service.version", "value": {"stringValue": env!("CARGO_PKG_VERSION")}},
    ]})
}

/// The OTLP/HTTP JSON bodies for a batch: metrics, then logs. `None` for a
/// signal with nothing in the batch.
fn bodies(batch: &[(u128, Record)]) -> (Option<serde_json::Value>, Option<serde_json::Value>) {
    let scope = serde_json::json!({"name": "orbit"});
    let mut metrics: Vec<serde_json::Value> = Vec::new();
    let mut logs: Vec<serde_json::Value> = Vec::new();
    for (at, record) in batch {
        match record {
            Record::Sum(name, unit, value, list) => metrics.push(serde_json::json!({
                "name": name,
                "unit": unit,
                "sum": {
                    // Each point is what was added since the last one.
                    "aggregationTemporality": 1,
                    "isMonotonic": true,
                    "dataPoints": [{
                        "asDouble": value,
                        "startTimeUnixNano": at.to_string(),
                        "timeUnixNano": at.to_string(),
                        "attributes": attributes(list),
                    }],
                },
            })),
            Record::Event(name, list) => logs.push(serde_json::json!({
                "timeUnixNano": at.to_string(),
                "observedTimeUnixNano": at.to_string(),
                "severityNumber": 9,
                "severityText": "INFO",
                "body": {"stringValue": name},
                "attributes": attributes(
                    &std::iter::once(("event.name", (*name).to_owned()))
                        .chain(list.iter().cloned())
                        .collect::<Vec<_>>(),
                ),
            })),
            // Spans are their own signal: see `trace_body`.
            Record::Span(_) => {}
        }
    }
    (
        (!metrics.is_empty()).then(|| {
            serde_json::json!({"resourceMetrics": [{
                "resource": resource(),
                "scopeMetrics": [{"scope": scope, "metrics": metrics}],
            }]})
        }),
        (!logs.is_empty()).then(|| {
            serde_json::json!({"resourceLogs": [{
                "resource": resource(),
                "scopeLogs": [{"scope": scope, "logRecords": logs}],
            }]})
        }),
    )
}

fn hex_id(id: &[u8]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn spans(batch: &[(u128, Record)]) -> impl Iterator<Item = &Span> {
    batch.iter().filter_map(|(_, record)| match record {
        Record::Span(span) => Some(span),
        _ => None,
    })
}

/// The OTLP/HTTP JSON body for the spans of a batch, if it has any.
fn trace_body(batch: &[(u128, Record)]) -> Option<serde_json::Value> {
    let listed: Vec<serde_json::Value> = spans(batch)
        .map(|span| {
            let mut json = serde_json::json!({
                "traceId": hex_id(&span.trace_id),
                "spanId": hex_id(&span.span_id),
                "name": span.name,
                // 1: an internal operation.
                "kind": 1,
                "startTimeUnixNano": span.start.to_string(),
                "endTimeUnixNano": span.end.to_string(),
                "attributes": attributes(&span.attributes),
                // 1: ok, 2: error.
                "status": {"code": if span.ok { 1 } else { 2 }},
            });
            if let Some(parent) = &span.parent {
                json["parentSpanId"] = hex_id(parent).into();
            }
            json
        })
        .collect();
    (!listed.is_empty()).then(|| {
        serde_json::json!({"resourceSpans": [{
            "resource": resource(),
            "scopeSpans": [{"scope": {"name": "orbit"}, "spans": listed}],
        }]})
    })
}

/// Protobuf's wire format, as far as OTLP's messages need it.
mod wire {
    pub fn varint(out: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            out.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }
    /// A length-delimited field: a message, a string or bytes.
    pub fn bytes(out: &mut Vec<u8>, field: u32, data: &[u8]) {
        varint(out, u64::from(field) << 3 | 2);
        varint(out, data.len() as u64);
        out.extend_from_slice(data);
    }
    pub fn string(out: &mut Vec<u8>, field: u32, text: &str) {
        bytes(out, field, text.as_bytes());
    }
    pub fn uint(out: &mut Vec<u8>, field: u32, value: u64) {
        varint(out, u64::from(field) << 3);
        varint(out, value);
    }
    pub fn fixed64(out: &mut Vec<u8>, field: u32, value: u64) {
        varint(out, u64::from(field) << 3 | 1);
        out.extend_from_slice(&value.to_le_bytes());
    }
    pub fn double(out: &mut Vec<u8>, field: u32, value: f64) {
        fixed64(out, field, value.to_bits());
    }
}

/// `KeyValue { key = 1; AnyValue value = 2 { string_value = 1 } }`.
fn proto_attribute(key: &str, value: &str) -> Vec<u8> {
    let mut any = Vec::new();
    wire::string(&mut any, 1, value);
    let mut pair = Vec::new();
    wire::string(&mut pair, 1, key);
    wire::bytes(&mut pair, 2, &any);
    pair
}

/// `Resource { repeated KeyValue attributes = 1 }`.
fn proto_resource() -> Vec<u8> {
    let mut resource = Vec::new();
    wire::bytes(&mut resource, 1, &proto_attribute("service.name", "orbit"));
    wire::bytes(
        &mut resource,
        1,
        &proto_attribute("service.version", env!("CARGO_PKG_VERSION")),
    );
    resource
}

/// `InstrumentationScope { name = 1 }`.
fn proto_scope() -> Vec<u8> {
    let mut scope = Vec::new();
    wire::string(&mut scope, 1, "orbit");
    scope
}

/// The OTLP protobuf messages for a batch: `ExportMetricsServiceRequest`,
/// then `ExportLogsServiceRequest`. `None` for a signal with nothing in
/// the batch. The same content as [`bodies`].
fn proto_bodies(batch: &[(u128, Record)]) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    // ScopeMetrics { scope = 1; repeated Metric metrics = 2 } and
    // ScopeLogs { scope = 1; repeated LogRecord log_records = 2 }.
    let (mut metrics, mut logs) = (Vec::new(), Vec::new());
    wire::bytes(&mut metrics, 1, &proto_scope());
    wire::bytes(&mut logs, 1, &proto_scope());
    let (mut any_metric, mut any_log) = (false, false);
    for (at, record) in batch {
        let at = u64::try_from(*at).unwrap_or(u64::MAX);
        match record {
            Record::Sum(name, unit, value, list) => {
                // NumberDataPoint { start_time_unix_nano = 2; time_unix_nano
                // = 3; as_double = 4; repeated KeyValue attributes = 7 }.
                let mut point = Vec::new();
                wire::fixed64(&mut point, 2, at);
                wire::fixed64(&mut point, 3, at);
                wire::double(&mut point, 4, *value);
                for (key, value) in list {
                    wire::bytes(&mut point, 7, &proto_attribute(key, value));
                }
                // Sum { data_points = 1; aggregation_temporality = 2
                // (1: delta); is_monotonic = 3 }.
                let mut sum = Vec::new();
                wire::bytes(&mut sum, 1, &point);
                wire::uint(&mut sum, 2, 1);
                wire::uint(&mut sum, 3, 1);
                // Metric { name = 1; unit = 3; sum = 7 }.
                let mut metric = Vec::new();
                wire::string(&mut metric, 1, name);
                wire::string(&mut metric, 3, unit);
                wire::bytes(&mut metric, 7, &sum);
                wire::bytes(&mut metrics, 2, &metric);
                any_metric = true;
            }
            Record::Event(name, list) => {
                // LogRecord { time_unix_nano = 1; severity_number = 2 (9:
                // INFO); severity_text = 3; AnyValue body = 5; repeated
                // KeyValue attributes = 6; observed_time_unix_nano = 11 }.
                let mut body = Vec::new();
                wire::string(&mut body, 1, name);
                let mut log = Vec::new();
                wire::fixed64(&mut log, 1, at);
                wire::uint(&mut log, 2, 9);
                wire::string(&mut log, 3, "INFO");
                wire::bytes(&mut log, 5, &body);
                wire::bytes(&mut log, 6, &proto_attribute("event.name", name));
                for (key, value) in list {
                    wire::bytes(&mut log, 6, &proto_attribute(key, value));
                }
                // observed_time_unix_nano = 11: when ORBIT saw the event,
                // which is when it happened.
                wire::fixed64(&mut log, 11, at);
                wire::bytes(&mut logs, 2, &log);
                any_log = true;
            }
            // Spans are their own signal: see `proto_trace_body`.
            Record::Span(_) => {}
        }
    }
    // Resource{Metrics,Logs} { resource = 1; repeated Scope… = 2 }, inside
    // the request's one repeated field (1).
    let request = |scoped: Vec<u8>| {
        let mut resource = Vec::new();
        wire::bytes(&mut resource, 1, &proto_resource());
        wire::bytes(&mut resource, 2, &scoped);
        let mut request = Vec::new();
        wire::bytes(&mut request, 1, &resource);
        request
    };
    (
        any_metric.then(|| request(metrics)),
        any_log.then(|| request(logs)),
    )
}

/// `ExportTraceServiceRequest` for the spans of a batch, if it has any.
/// The same content as [`trace_body`].
fn proto_trace_body(batch: &[(u128, Record)]) -> Option<Vec<u8>> {
    // ScopeSpans { scope = 1; repeated Span spans = 2 }.
    let mut scoped = Vec::new();
    wire::bytes(&mut scoped, 1, &proto_scope());
    let mut any = false;
    for span in spans(batch) {
        // Span { trace_id = 1; span_id = 2; parent_span_id = 4; name = 5;
        // kind = 6 (1: internal); start_time_unix_nano = 7;
        // end_time_unix_nano = 8; repeated KeyValue attributes = 9;
        // Status status = 15 { code = 3 (1: ok, 2: error) } }.
        let mut message = Vec::new();
        wire::bytes(&mut message, 1, &span.trace_id);
        wire::bytes(&mut message, 2, &span.span_id);
        if let Some(parent) = &span.parent {
            wire::bytes(&mut message, 4, parent);
        }
        wire::string(&mut message, 5, span.name);
        wire::uint(&mut message, 6, 1);
        wire::fixed64(
            &mut message,
            7,
            u64::try_from(span.start).unwrap_or(u64::MAX),
        );
        wire::fixed64(&mut message, 8, u64::try_from(span.end).unwrap_or(u64::MAX));
        for (key, value) in &span.attributes {
            wire::bytes(&mut message, 9, &proto_attribute(key, value));
        }
        let mut status = Vec::new();
        wire::uint(&mut status, 3, if span.ok { 1 } else { 2 });
        wire::bytes(&mut message, 15, &status);
        wire::bytes(&mut scoped, 2, &message);
        any = true;
    }
    any.then(|| {
        // ResourceSpans { resource = 1; repeated ScopeSpans = 2 }, inside
        // the request's one repeated field (1).
        let mut resource = Vec::new();
        wire::bytes(&mut resource, 1, &proto_resource());
        wire::bytes(&mut resource, 2, &scoped);
        let mut request = Vec::new();
        wire::bytes(&mut request, 1, &resource);
        request
    })
}

/// The spans of a batch as they are sent in `protocol`.
fn trace_payload(protocol: Protocol, batch: &[(u128, Record)]) -> Option<Vec<u8>> {
    match protocol {
        Protocol::HttpJson => trace_body(batch).map(|body| body.to_string().into_bytes()),
        Protocol::HttpProtobuf => proto_trace_body(batch),
        Protocol::Grpc => proto_trace_body(batch).map(|message| {
            let mut frame = vec![0_u8];
            frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
            frame.extend_from_slice(&message);
            frame
        }),
    }
}

/// What is sent for a batch in `protocol`: metrics, then logs.
fn payloads(protocol: Protocol, batch: &[(u128, Record)]) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    match protocol {
        Protocol::HttpJson => {
            let (metrics, logs) = bodies(batch);
            let bytes = |body: serde_json::Value| body.to_string().into_bytes();
            (metrics.map(bytes), logs.map(bytes))
        }
        Protocol::HttpProtobuf => proto_bodies(batch),
        Protocol::Grpc => {
            // One uncompressed gRPC message: a zero byte, the length in
            // four bytes, the message.
            let frame = |message: Vec<u8>| {
                let mut frame = vec![0_u8];
                frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
                frame.extend_from_slice(&message);
                frame
            };
            let (metrics, logs) = proto_bodies(batch);
            (metrics.map(frame), logs.map(frame))
        }
    }
}

/// The `curl` arguments that say how `protocol` is spoken to `url`.
fn transport_arguments(protocol: Protocol, url: &str) -> Vec<&'static str> {
    match protocol {
        Protocol::HttpJson => vec!["--header", "Content-Type: application/json"],
        Protocol::HttpProtobuf => vec!["--header", "Content-Type: application/x-protobuf"],
        Protocol::Grpc => vec![
            // gRPC is HTTP/2 only: negotiated with TLS, assumed without.
            if url.starts_with("https://") {
                "--http2"
            } else {
                "--http2-prior-knowledge"
            },
            "--header",
            "Content-Type: application/grpc",
            "--header",
            "TE: trailers",
        ],
    }
}

/// One POST of a body: `curl`, no shell, five seconds at most.
fn post(protocol: Protocol, url: &str, headers: &[(String, String)], body: &[u8]) {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut curl = Command::new("curl");
    curl.args(["--silent", "--max-time", "5", "--request", "POST"])
        .args(transport_arguments(protocol, url));
    for (name, value) in headers {
        curl.arg("--header").arg(format!("{name}: {value}"));
    }
    curl.args(["--data-binary", "@-", "--"])
        .arg(url)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let Ok(mut child) = curl.spawn() else {
        return;
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(body);
    }
    let _ = child.wait();
}

/// One POST per signal that has an endpoint and something in the batch,
/// each in its own protocol.
fn send(exporter: &Exporter, batch: &[(u128, Record)]) {
    if let Some(url) = &exporter.metrics_url
        && let (Some(body), _) = payloads(exporter.metrics_protocol, batch)
    {
        post(exporter.metrics_protocol, url, &exporter.headers, &body);
    }
    if let Some(url) = &exporter.logs_url
        && let (_, Some(body)) = payloads(exporter.logs_protocol, batch)
    {
        post(exporter.logs_protocol, url, &exporter.headers, &body);
    }
    if let Some(url) = &exporter.traces_url
        && let Some(body) = trace_payload(exporter.traces_protocol, batch)
    {
        post(exporter.traces_protocol, url, &exporter.headers, &body);
    }
}

/// Send what is waiting, off this thread.
fn flush(exporter: &Exporter) {
    let batch = match PENDING.lock() {
        Ok(mut pending) => std::mem::take(&mut *pending),
        Err(_) => return,
    };
    if batch.is_empty() {
        return;
    }
    let exporter = exporter.clone();
    let _ = std::thread::Builder::new()
        .name("orbit-telemetry".into())
        .spawn(move || {
            send(&exporter, &batch);
        });
}

/// Send what is waiting and give the exports a moment: for a process that
/// is about to exit.
pub fn finish(home: &Path) {
    let Some(exporter) = exporter(home) else {
        return;
    };
    let batch = match PENDING.lock() {
        Ok(mut pending) => std::mem::take(&mut *pending),
        Err(_) => return,
    };
    if batch.is_empty() {
        return;
    }
    send(&exporter, &batch);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(known, _)| *known == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    /// Telemetry is off until it is switched on and given an endpoint in a
    /// protocol ORBIT speaks.
    #[test]
    fn the_exporter_needs_the_switch_an_endpoint_and_a_known_protocol() {
        assert_eq!(exporter_from(&env(&[]), false), None);
        assert_eq!(
            exporter_from(
                &env(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")]),
                false
            ),
            None,
            "an endpoint alone is not consent"
        );
        assert_eq!(
            exporter_from(&env(&[("ORBIT_ENABLE_TELEMETRY", "1")]), false),
            None,
            "nowhere to send"
        );
        let on = exporter_from(
            &env(&[
                ("ORBIT_ENABLE_TELEMETRY", "1"),
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318/"),
                (
                    "OTEL_EXPORTER_OTLP_HEADERS",
                    "Authorization=Bearer abc, x-team = core,bad name=1",
                ),
            ]),
            false,
        )
        .unwrap();
        assert_eq!(
            on.metrics_url.as_deref(),
            Some("http://127.0.0.1:4318/v1/metrics")
        );
        assert_eq!(
            on.logs_url.as_deref(),
            Some("http://127.0.0.1:4318/v1/logs")
        );
        assert_eq!(
            on.headers,
            [
                ("Authorization".to_owned(), "Bearer abc".to_owned()),
                ("x-team".to_owned(), "core".to_owned())
            ]
        );
        // One signal with its own endpoint; the other has none.
        let logs_only = exporter_from(
            &env(&[
                ("ORBIT_ENABLE_TELEMETRY", "true"),
                (
                    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
                    "https://logs.example/v1/logs",
                ),
            ]),
            false,
        )
        .unwrap();
        assert_eq!(logs_only.metrics_url, None);
        assert_eq!(
            logs_only.logs_url.as_deref(),
            Some("https://logs.example/v1/logs")
        );
        // Claude Code's switch counts only with the compat setting on.
        let claude = [
            ("CLAUDE_CODE_ENABLE_TELEMETRY", "1"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318"),
        ];
        assert_eq!(exporter_from(&env(&claude), false), None);
        assert!(exporter_from(&env(&claude), true).is_some());
        assert_eq!(
            (on.metrics_protocol, on.logs_protocol),
            (Protocol::HttpJson, Protocol::HttpJson)
        );
        let spoken = |protocol: &str, extra: &[(&str, &str)]| {
            let mut pairs = vec![
                ("ORBIT_ENABLE_TELEMETRY", "1"),
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4317/"),
                ("OTEL_EXPORTER_OTLP_PROTOCOL", protocol),
            ];
            pairs.extend_from_slice(extra);
            exporter_from(&env(&pairs), false)
        };
        let protobuf = spoken("http/protobuf", &[]).unwrap();
        assert_eq!(protobuf.metrics_protocol, Protocol::HttpProtobuf);
        assert_eq!(protobuf.logs_protocol, Protocol::HttpProtobuf);
        assert_eq!(
            protobuf.logs_url.as_deref(),
            Some("http://127.0.0.1:4317/v1/logs")
        );
        // gRPC: the endpoint is an address and the call's path is fixed,
        // also for a signal with an address of its own.
        let grpc = spoken(
            "grpc",
            &[(
                "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
                "https://logs.example:4317/",
            )],
        )
        .unwrap();
        assert_eq!(grpc.metrics_protocol, Protocol::Grpc);
        assert_eq!(
            grpc.metrics_url.as_deref(),
            Some(
                "http://127.0.0.1:4317/opentelemetry.proto.collector.metrics.v1.MetricsService/Export"
            )
        );
        assert_eq!(
            grpc.logs_url.as_deref(),
            Some(
                "https://logs.example:4317/opentelemetry.proto.collector.logs.v1.LogsService/Export"
            )
        );
        assert_eq!(spoken("http/thrift", &[]), None, "an unknown protocol");
        // A signal may speak its own protocol, and one that names an
        // unknown protocol is not exported while the other still is.
        let mixed = spoken(
            "grpc",
            &[
                ("OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", "http/protobuf"),
                (
                    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
                    "http://127.0.0.1:4318/v1/logs",
                ),
            ],
        )
        .unwrap();
        assert_eq!(mixed.metrics_protocol, Protocol::Grpc);
        assert_eq!(mixed.logs_protocol, Protocol::HttpProtobuf);
        assert_eq!(
            mixed.logs_url.as_deref(),
            Some("http://127.0.0.1:4318/v1/logs")
        );
        let one = spoken(
            "",
            &[("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", "carrier-pigeon")],
        )
        .unwrap();
        assert_eq!(one.metrics_url, None);
        assert_eq!(
            one.logs_url.as_deref(),
            Some("http://127.0.0.1:4317/v1/logs")
        );
        assert_eq!(
            exporter_from(
                &env(&[
                    ("ORBIT_ENABLE_TELEMETRY", "1"),
                    ("OTEL_EXPORTER_OTLP_ENDPOINT", "file:///etc/passwd"),
                ]),
                false
            ),
            None
        );
    }

    /// A turn becomes token and cost counters and one event, in OTLP's
    /// JSON shape, and carries no text of the conversation.
    #[test]
    fn a_turn_is_exported_as_counters_and_one_event() {
        let turn = Turn {
            session_id: "session-1".into(),
            model: "big".into(),
            provider: "acme".into(),
            input_tokens: 1200,
            output_tokens: 300,
            cache_read_tokens: 900,
            cache_write_tokens: 0,
            cost_microdollars: 4_500,
            rounds: 3,
            ok: true,
        };
        let batch: Vec<(u128, Record)> = turn_records(&turn)
            .into_iter()
            .chain([Record::Event(
                "orbit.tool_result",
                vec![
                    ("tool_name", "Bash".to_owned()),
                    ("success", "false".to_owned()),
                ],
            )])
            .map(|record| (1_700_000_000_000_000_000, record))
            .collect();
        let (metrics, logs) = bodies(&batch);
        let metrics = metrics.unwrap();
        let points = metrics["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .unwrap();
        let named: Vec<(&str, f64, String)> = points
            .iter()
            .map(|metric| {
                let point = &metric["sum"]["dataPoints"][0];
                (
                    metric["name"].as_str().unwrap(),
                    point["asDouble"].as_f64().unwrap(),
                    point["attributes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|attribute| attribute["key"] == "type")
                        .map_or(String::new(), |attribute| {
                            attribute["value"]["stringValue"]
                                .as_str()
                                .unwrap()
                                .to_owned()
                        }),
                )
            })
            .collect();
        assert_eq!(
            named,
            [
                ("orbit.token.usage", 1200.0, "input".to_owned()),
                ("orbit.token.usage", 300.0, "output".to_owned()),
                ("orbit.token.usage", 900.0, "cacheRead".to_owned()),
                ("orbit.cost.usage", 0.0045, String::new()),
            ],
            "a zero count is not a point"
        );
        assert_eq!(points[0]["sum"]["aggregationTemporality"], 1);
        assert_eq!(
            points[0]["sum"]["dataPoints"][0]["timeUnixNano"],
            "1700000000000000000"
        );
        assert_eq!(
            metrics["resourceMetrics"][0]["resource"]["attributes"][0]["value"]["stringValue"],
            "orbit"
        );
        let logs = logs.unwrap();
        let records = logs["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
            .as_array()
            .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["body"]["stringValue"], "orbit.api_request");
        assert_eq!(records[1]["body"]["stringValue"], "orbit.tool_result");
        let text = logs.to_string();
        assert!(
            text.contains(r#"{"key":"success","value":{"stringValue":"true"}}"#),
            "{text}"
        );
        assert!(text.contains(r#"{"key":"cost_usd","value":{"stringValue":"0.004500"}}"#));
        assert_eq!(bodies(&[]), (None, None));
    }

    /// The export itself: one POST per signal reaches a local collector
    /// with the JSON content type and the operator's headers.
    #[test]
    fn a_batch_is_posted_to_the_collector() {
        if std::process::Command::new("curl")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .status()
            .is_err()
        {
            return; // no curl here: nothing to exercise
        }
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let collector = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut chunk = [0_u8; 4096];
            // Headers, then as many body bytes as Content-Length says.
            loop {
                let n = stream.read(&mut chunk).unwrap();
                seen.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&seen).into_owned();
                if let Some(end) = text.find("\r\n\r\n") {
                    let length: usize = text[..end]
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|value| value.trim().parse().unwrap())
                        })
                        .unwrap_or(0);
                    if seen.len() >= end + 4 + length || n == 0 {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .unwrap();
            String::from_utf8_lossy(&seen).into_owned()
        });
        post(
            Protocol::HttpJson,
            &format!("http://127.0.0.1:{port}/v1/logs"),
            &[("x-team".to_owned(), "core".to_owned())],
            br#"{"resourceLogs":[]}"#,
        );
        let request = collector.join().unwrap();
        assert!(request.starts_with("POST /v1/logs HTTP/1.1"), "{request}");
        let lower = request.to_ascii_lowercase();
        assert!(
            lower.contains("content-type: application/json"),
            "{request}"
        );
        assert!(lower.contains("x-team: core"), "{request}");
        assert!(request.ends_with(r#"{"resourceLogs":[]}"#), "{request}");
    }

    /// Spans go out only when asked for, as one trace per turn: the tool
    /// calls under the turn, in both forms, with nothing of the content.
    #[test]
    fn a_turn_and_its_tools_are_one_trace() {
        let base = [
            ("ORBIT_ENABLE_TELEMETRY", "1"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318"),
        ];
        let off = exporter_from(&env(&base), false).unwrap();
        assert_eq!(off.traces_url, None, "spans are a separate choice");
        let mut with = base.to_vec();
        with.extend([
            ("OTEL_TRACES_EXPORTER", "otlp"),
            ("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "grpc"),
        ]);
        let on = exporter_from(&env(&with), false).unwrap();
        assert_eq!(
            on.traces_url.as_deref(),
            Some(
                "http://127.0.0.1:4318/opentelemetry.proto.collector.trace.v1.TraceService/Export"
            )
        );
        assert_eq!(on.traces_protocol, Protocol::Grpc);
        assert_eq!(on.logs_protocol, Protocol::HttpJson);

        let (trace_id, root) = ([7_u8; 16], [1_u8; 8]);
        let batch = [
            (
                0,
                Record::Span(Span {
                    name: "orbit.tool",
                    trace_id,
                    span_id: [2; 8],
                    parent: Some(root),
                    start: 1_700_000_000_000_000_100,
                    end: 1_700_000_000_000_000_900,
                    ok: false,
                    attributes: vec![("tool_name", "Bash".to_owned())],
                }),
            ),
            (
                0,
                Record::Span(Span {
                    name: "orbit.turn",
                    trace_id,
                    span_id: root,
                    parent: None,
                    start: 1_700_000_000_000_000_000,
                    end: 1_700_000_000_000_001_000,
                    ok: true,
                    attributes: vec![("model", "big".to_owned())],
                }),
            ),
            (5, Record::Event("orbit.tool_result", Vec::new())),
        ];
        // The other signals do not carry spans.
        let (metrics, logs) = bodies(&batch);
        assert!(metrics.is_none());
        assert_eq!(
            logs.unwrap()["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let json = trace_body(&batch).unwrap();
        let listed = json["resourceSpans"][0]["scopeSpans"][0]["spans"]
            .as_array()
            .unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0]["traceId"], "07".repeat(16));
        assert_eq!(listed[0]["spanId"], "02".repeat(8));
        assert_eq!(listed[0]["parentSpanId"], "01".repeat(8));
        assert_eq!(listed[0]["status"]["code"], 2);
        assert_eq!(listed[0]["startTimeUnixNano"], "1700000000000000100");
        assert_eq!(listed[1]["name"], "orbit.turn");
        assert!(listed[1].get("parentSpanId").is_none());
        assert_eq!(listed[1]["status"]["code"], 1);

        // ExportTraceServiceRequest.resource_spans (1).
        let request = read(&proto_trace_body(&batch).unwrap()).unwrap();
        let scope_spans = &message(&message(&request, 1)[0], 2)[0];
        let written = message(scope_spans, 2);
        assert_eq!(written.len(), 2);
        let tool = &written[0];
        assert!(tool.contains(&Field::Bytes(1, trace_id.to_vec())));
        assert!(tool.contains(&Field::Bytes(2, vec![2; 8])));
        assert!(tool.contains(&Field::Bytes(4, root.to_vec())));
        assert_eq!(text(tool, 5), "orbit.tool");
        assert!(tool.contains(&Field::Varint(6, 1)));
        assert!(tool.contains(&Field::Fixed64(7, 1_700_000_000_000_000_100)));
        assert!(tool.contains(&Field::Fixed64(8, 1_700_000_000_000_000_900)));
        assert_eq!(
            pairs(tool, 9),
            [("tool_name".to_owned(), "Bash".to_owned())]
        );
        assert_eq!(message(tool, 15)[0], [Field::Varint(3, 2)]);
        let turn = &written[1];
        assert!(!turn.iter().any(|field| matches!(field, Field::Bytes(4, _))));
        assert_eq!(message(turn, 15)[0], [Field::Varint(3, 1)]);
        assert!(proto_trace_body(&batch[2..]).is_none());
        assert!(trace_body(&[]).is_none());
        let id: [u8; 8] = random_id();
        assert_ne!(id, [0; 8]);
    }

    /// A protobuf field as it was written: its number and its value.
    #[derive(Debug, Clone, PartialEq)]
    enum Field {
        Varint(u32, u64),
        Fixed64(u32, u64),
        Bytes(u32, Vec<u8>),
    }

    /// Read a message back, field by field; `None` when it is not one.
    fn read(mut data: &[u8]) -> Option<Vec<Field>> {
        fn varint(data: &mut &[u8]) -> Option<u64> {
            let mut value = 0_u64;
            for shift in (0..64).step_by(7) {
                let (byte, rest) = data.split_first()?;
                *data = rest;
                value |= u64::from(byte & 0x7f) << shift;
                if byte & 0x80 == 0 {
                    return Some(value);
                }
            }
            None
        }
        let mut fields = Vec::new();
        while !data.is_empty() {
            let key = varint(&mut data)?;
            let field = u32::try_from(key >> 3).ok()?;
            match key & 7 {
                0 => fields.push(Field::Varint(field, varint(&mut data)?)),
                1 => {
                    let (value, rest) = data.split_first_chunk::<8>()?;
                    data = rest;
                    fields.push(Field::Fixed64(field, u64::from_le_bytes(*value)));
                }
                2 => {
                    let length = usize::try_from(varint(&mut data)?).ok()?;
                    let (value, rest) = data.split_at_checked(length)?;
                    data = rest;
                    fields.push(Field::Bytes(field, value.to_vec()));
                }
                _ => return None,
            }
        }
        Some(fields)
    }

    fn message(fields: &[Field], number: u32) -> Vec<Vec<Field>> {
        fields
            .iter()
            .filter_map(|field| match field {
                Field::Bytes(found, data) if *found == number => read(data),
                _ => None,
            })
            .collect()
    }

    fn text(fields: &[Field], number: u32) -> String {
        fields
            .iter()
            .find_map(|field| match field {
                Field::Bytes(found, data) if *found == number => {
                    Some(String::from_utf8(data.clone()).unwrap())
                }
                _ => None,
            })
            .unwrap_or_default()
    }

    /// `KeyValue`s as (key, string value).
    fn pairs(fields: &[Field], number: u32) -> Vec<(String, String)> {
        message(fields, number)
            .iter()
            .map(|pair| (text(pair, 1), text(&message(pair, 2)[0], 1)))
            .collect()
    }

    /// The protobuf form says what the JSON form says, in the fields the
    /// published OTLP messages give them.
    #[test]
    fn the_protobuf_form_carries_the_same_batch() {
        let at = 1_700_000_000_000_000_000_u64;
        let batch = [
            (
                u128::from(at),
                Record::Sum(
                    "orbit.token.usage",
                    "tokens",
                    1200.0,
                    vec![
                        ("session.id", "s-1".to_owned()),
                        ("type", "input".to_owned()),
                    ],
                ),
            ),
            (
                u128::from(at),
                Record::Sum("orbit.cost.usage", "USD", 0.0045, Vec::new()),
            ),
            (
                u128::from(at),
                Record::Event(
                    "orbit.tool_result",
                    vec![("tool_name", "Bash — ç".to_owned())],
                ),
            ),
        ];
        let (metrics, logs) = proto_bodies(&batch);

        // ExportMetricsServiceRequest.resource_metrics (1).
        let request = read(&metrics.unwrap()).unwrap();
        let resource_metrics = &message(&request, 1)[0];
        assert_eq!(
            pairs(&message(resource_metrics, 1)[0], 1),
            [
                ("service.name".to_owned(), "orbit".to_owned()),
                (
                    "service.version".to_owned(),
                    env!("CARGO_PKG_VERSION").to_owned()
                ),
            ]
        );
        let scope_metrics = &message(resource_metrics, 2)[0];
        assert_eq!(text(&message(scope_metrics, 1)[0], 1), "orbit");
        let listed = message(scope_metrics, 2);
        assert_eq!(listed.len(), 2);
        assert_eq!(text(&listed[0], 1), "orbit.token.usage");
        assert_eq!(text(&listed[0], 3), "tokens");
        let sum = &message(&listed[0], 7)[0];
        assert!(sum.contains(&Field::Varint(2, 1)), "delta");
        assert!(sum.contains(&Field::Varint(3, 1)), "monotonic");
        let point = &message(sum, 1)[0];
        assert_eq!(
            point[..3],
            [
                Field::Fixed64(2, at),
                Field::Fixed64(3, at),
                Field::Fixed64(4, 1200.0_f64.to_bits()),
            ]
        );
        assert_eq!(
            pairs(point, 7),
            [
                ("session.id".to_owned(), "s-1".to_owned()),
                ("type".to_owned(), "input".to_owned())
            ]
        );
        let cost = &message(&message(&listed[1], 7)[0], 1)[0];
        assert!(cost.contains(&Field::Fixed64(4, 0.0045_f64.to_bits())));

        // ExportLogsServiceRequest.resource_logs (1).
        let request = read(&logs.unwrap()).unwrap();
        let scope_logs = &message(&message(&request, 1)[0], 2)[0];
        let records = message(scope_logs, 2);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0][0], Field::Fixed64(1, at));
        assert!(records[0].contains(&Field::Fixed64(11, at)));
        assert!(records[0].contains(&Field::Varint(2, 9)));
        assert_eq!(text(&records[0], 3), "INFO");
        assert_eq!(text(&message(&records[0], 5)[0], 1), "orbit.tool_result");
        assert_eq!(
            pairs(&records[0], 6),
            [
                ("event.name".to_owned(), "orbit.tool_result".to_owned()),
                ("tool_name".to_owned(), "Bash — ç".to_owned())
            ]
        );

        assert_eq!(proto_bodies(&[]), (None, None));
        // A gRPC frame is the message behind a zero and its length.
        let (plain, _) = payloads(Protocol::HttpProtobuf, &batch);
        let (framed, _) = payloads(Protocol::Grpc, &batch);
        let (plain, framed) = (plain.unwrap(), framed.unwrap());
        assert_eq!(framed[0], 0);
        assert_eq!(
            u32::from_be_bytes(framed[1..5].try_into().unwrap()) as usize,
            plain.len()
        );
        assert_eq!(framed[5..], plain[..]);
        // A length that needs two varint bytes is written as such.
        let mut long = Vec::new();
        wire::string(&mut long, 1, &"x".repeat(300));
        assert_eq!(long[..3], [0x0a, 0xac, 0x02]);
        assert_eq!(
            transport_arguments(Protocol::Grpc, "https://c.example:4317/x")[0],
            "--http2"
        );
        assert_eq!(
            transport_arguments(Protocol::Grpc, "http://127.0.0.1:4317/x")[0],
            "--http2-prior-knowledge"
        );
        assert!(
            transport_arguments(Protocol::HttpProtobuf, "http://c/x")
                .contains(&"Content-Type: application/x-protobuf")
        );
    }
}
