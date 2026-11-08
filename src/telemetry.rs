//! OpenTelemetry span and metric batch emitter streaming `MUOB`-framed Apache Arrow
//! batches from `MuConDe-agent` to the local `MuObserve-collector`.

#![deny(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use mu_observable_ipc::{
    encode_metric_batch, encode_span_batch, write_frame, DeterministicSecretRedactor, IpcHeader,
    OtelMetricEntry, OtelSpanEntry, TraceContext, MSG_TYPE_ARROW_OTEL_METRICS,
    MSG_TYPE_ARROW_OTEL_SPANS,
};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Default local `MuObserve-collector` native `MUOB` Arrow IPC ingestion address.
pub const DEFAULT_COLLECTOR_ADDR: &str = "127.0.0.1:4319";

/// Canonical service name emitted on `MuConDe-agent` spans and metrics.
pub const AGENT_SERVICE_NAME: &str = "muconde-agent";

/// Current timestamp in nanoseconds since Unix epoch.
#[must_use]
pub fn now_unix_nano() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Abstract sink receiving OpenTelemetry span and metric batches from `MuConDe-agent`.
#[async_trait]
pub trait TelemetrySink: Send + Sync {
    /// Emits a batch of [`OtelSpanEntry`] records.
    async fn emit_spans(&self, spans: Vec<OtelSpanEntry>);

    /// Emits a batch of [`OtelMetricEntry`] records.
    async fn emit_metrics(&self, metrics: Vec<OtelMetricEntry>);
}

/// Network sink streaming `MUOB`-framed Arrow batches (`MSG_TYPE_ARROW_OTEL_SPANS` and
/// `MSG_TYPE_ARROW_OTEL_METRICS`) to the local `MuObserve-collector` with non-blocking
/// graceful fallback if the collector is unreachable.
#[derive(Debug)]
pub struct MuObserveCollectorSink {
    collector_addr: Option<String>,
    sequence: AtomicU64,
    connect_timeout: Duration,
}

impl MuObserveCollectorSink {
    /// Creates a new sink targeting `collector_addr` (or disabled if `None`).
    #[must_use]
    pub fn new(collector_addr: Option<String>) -> Self {
        Self {
            collector_addr,
            sequence: AtomicU64::new(1),
            connect_timeout: Duration::from_millis(500),
        }
    }

    async fn send_frame(&self, msg_type: u16, payload: Vec<u8>) {
        let Some(ref addr) = self.collector_addr else {
            return;
        };
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let header = IpcHeader::new(msg_type, payload.len() as u32, 0, seq);

        let connect_fut = TcpStream::connect(addr);
        match tokio::time::timeout(self.connect_timeout, connect_fut).await {
            Ok(Ok(mut stream)) => {
                if let Err(e) = write_frame(&mut stream, &header, &payload).await {
                    tracing::debug!(
                        collector = %addr,
                        error = %e,
                        "Non-blocking fallback: failed to write MUOB telemetry frame to collector"
                    );
                }
            }
            Ok(Err(e)) => {
                tracing::debug!(
                    collector = %addr,
                    error = %e,
                    "Non-blocking fallback: local MuObserve-collector unreachable"
                );
            }
            Err(_) => {
                tracing::debug!(
                    collector = %addr,
                    "Non-blocking fallback: connection to local MuObserve-collector timed out"
                );
            }
        }
    }
}

#[async_trait]
impl TelemetrySink for MuObserveCollectorSink {
    async fn emit_spans(&self, mut spans: Vec<OtelSpanEntry>) {
        if spans.is_empty() || self.collector_addr.is_none() {
            return;
        }
        let redactor = DeterministicSecretRedactor::new();
        for span in &mut spans {
            span.redact_in_place(&redactor);
        }
        if let Ok(bytes) = encode_span_batch(&spans) {
            self.send_frame(MSG_TYPE_ARROW_OTEL_SPANS, bytes).await;
        }
    }

    async fn emit_metrics(&self, metrics: Vec<OtelMetricEntry>) {
        if metrics.is_empty() || self.collector_addr.is_none() {
            return;
        }
        if let Ok(bytes) = encode_metric_batch(&metrics) {
            self.send_frame(MSG_TYPE_ARROW_OTEL_METRICS, bytes).await;
        }
    }
}

/// In-memory recording sink for deterministic unit and integration testing, with optional
/// forwarding to a live [`MuObserveCollectorSink`].
#[derive(Default)]
pub struct RecordingTelemetrySink {
    spans: Mutex<Vec<OtelSpanEntry>>,
    metrics: Mutex<Vec<OtelMetricEntry>>,
    forward_to: Option<Arc<dyn TelemetrySink>>,
}

impl RecordingTelemetrySink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_forwarder(mut self, sink: Arc<dyn TelemetrySink>) -> Self {
        self.forward_to = Some(sink);
        self
    }

    pub async fn recorded_spans(&self) -> Vec<OtelSpanEntry> {
        self.spans.lock().await.clone()
    }

    pub async fn recorded_metrics(&self) -> Vec<OtelMetricEntry> {
        self.metrics.lock().await.clone()
    }
}

#[async_trait]
impl TelemetrySink for RecordingTelemetrySink {
    async fn emit_spans(&self, mut spans: Vec<OtelSpanEntry>) {
        let redactor = DeterministicSecretRedactor::new();
        for span in &mut spans {
            span.redact_in_place(&redactor);
        }
        self.spans.lock().await.extend(spans.clone());
        if let Some(ref fwd) = self.forward_to {
            fwd.emit_spans(spans).await;
        }
    }

    async fn emit_metrics(&self, metrics: Vec<OtelMetricEntry>) {
        self.metrics.lock().await.extend(metrics.clone());
        if let Some(ref fwd) = self.forward_to {
            fwd.emit_metrics(metrics).await;
        }
    }
}

/// Generates a deterministic W3C [`TraceContext`] from a deployment identifier and step seed.
#[must_use]
pub fn trace_context_for_deployment(deployment_id: &str, step_seed: u64) -> TraceContext {
    let mut hi: u64 = 0xcbf2_9ce4_8422_2325;
    let mut lo: u64 = 0x8422_2325_cbf2_9ce4;
    for (idx, b) in deployment_id.bytes().enumerate() {
        if idx % 2 == 0 {
            hi = (hi ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        } else {
            lo = (lo ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    let span_seed = hi
        .wrapping_add(lo)
        .wrapping_add(step_seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    TraceContext::from_seed(hi, lo, span_seed, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mu_observable_ipc::{decode_metric_batch, decode_span_batch, read_frame};
    use tokio::net::TcpListener;

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_collector_sink_streams_muob_arrow_batches_and_gracefully_handles_unreachable() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind collector");
        let addr = listener.local_addr().expect("addr");

        let server_task = tokio::spawn(async move {
            let (mut s1, _) = listener.accept().await.expect("accept span frame");
            let (h1, p1) = read_frame(&mut s1).await.expect("read span frame");
            assert_eq!(h1.msg_type, MSG_TYPE_ARROW_OTEL_SPANS);
            let spans = decode_span_batch(&p1).expect("decode spans");

            let (mut s2, _) = listener.accept().await.expect("accept metric frame");
            let (h2, p2) = read_frame(&mut s2).await.expect("read metric frame");
            assert_eq!(h2.msg_type, MSG_TYPE_ARROW_OTEL_METRICS);
            let metrics = decode_metric_batch(&p2).expect("decode metrics");

            (spans, metrics)
        });

        let sink = MuObserveCollectorSink::new(Some(addr.to_string()));
        let trace_ctx = trace_context_for_deployment("dep-test-1", 1);

        let span = OtelSpanEntry {
            trace_id: trace_ctx.trace_id_hex(),
            span_id: trace_ctx.span_id_hex(),
            parent_span_id: None,
            service_name: AGENT_SERVICE_NAME.to_string(),
            node_id: "worker-riscv64".to_string(),
            span_name: "muconde.agent.slot_swap".to_string(),
            span_kind: "INTERNAL".to_string(),
            start_time_unix_nano: 1_700_000_000_000_000_000,
            end_time_unix_nano: 1_700_000_000_005_000_000,
            duration_ns: 5_000_000,
            status_code: "OK".to_string(),
            status_message: None,
            attributes_json: r#"{"to_slot":"@b"}"#.to_string(),
        };
        let metric = OtelMetricEntry {
            timestamp_unix_nano: 1_700_000_000_005_000_000,
            service_name: AGENT_SERVICE_NAME.to_string(),
            node_id: "worker-riscv64".to_string(),
            metric_name: "muconde.agent.slot_probe_latency_ms".to_string(),
            metric_unit: "ms".to_string(),
            value_f64: 4.0,
            arch: std::env::consts::ARCH.to_string(),
            cpu_cluster: None,
            vlen_bits: None,
            memlock_used_bytes: None,
            memlock_limit_bytes: None,
            trace_id: Some(trace_ctx.trace_id_hex()),
            span_id: Some(trace_ctx.span_id_hex()),
            attributes_json: r#"{"service":"action-runner","slot":"@b"}"#.to_string(),
        };

        sink.emit_spans(vec![span.clone()]).await;
        sink.emit_metrics(vec![metric.clone()]).await;

        let (rx_spans, rx_metrics) = server_task.await.expect("collector task");
        assert_eq!(rx_spans, vec![span]);
        assert_eq!(rx_metrics, vec![metric]);

        // Unreachable collector should not panic or fail
        let dead_sink = MuObserveCollectorSink::new(Some("127.0.0.1:1".to_string()));
        dead_sink.emit_spans(rx_spans).await;
        dead_sink.emit_metrics(rx_metrics).await;
    }
}
