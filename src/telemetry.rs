use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Initialise the tracing subscriber.
///
/// Always adds a human-readable stderr formatter. Log level is controlled via
/// `RUST_LOG` (defaults to `warn`).
///
/// When the `otel` feature is compiled in **and** `OTEL_EXPORTER_OTLP_ENDPOINT`
/// is set at runtime, traces are also exported to that OTLP/gRPC endpoint.
pub fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));

    let fmt_layer = tracing_subscriber::fmt::layer();

    #[cfg(feature = "otel")]
    {
        if let Ok(endpoint) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
            use opentelemetry::trace::TracerProvider as _;
            use opentelemetry_otlp::WithExportConfig;

            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()
                .expect("failed to build OTLP span exporter");

            let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .build();

            let otel_layer =
                tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("camoflage"));

            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .with(otel_layer)
                .init();
            return;
        }
    }

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();
}
