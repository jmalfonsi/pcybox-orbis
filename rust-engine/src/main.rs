mod capture;
mod process;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::Response,
    routing::{get, post},
    Json, Router,
};
use capture::{CaptureMetrics, RawPacket};
use chrono::{Duration as ChronoDuration, SecondsFormat, Utc};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    net::TcpListener,
    sync::{broadcast, mpsc, RwLock},
};
use tower_http::cors::CorsLayer;

#[derive(Clone, Serialize)]
struct ProcCounters {
    bytes: u64,
    packets: u64,
}

#[derive(Clone, Serialize)]
struct Node {
    id: String,
    label: String,
    ip: String,
    country: Option<String>,
    country_code: Option<String>,
    city: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    org: Option<String>,
    category: String,
    color: String,
    bytes: u64,
    packets: u64,
    alerted: bool,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    processes: HashMap<String, ProcCounters>,
}

#[derive(Clone, Serialize)]
struct Edge {
    id: String,
    source: String,
    target: String,
    protocol: String,
    label: String,
    color: String,
    bytes: u64,
    packets: u64,
}

struct Graph {
    nodes: HashMap<String, Node>,
    edges: HashMap<String, Edge>,
}

impl Graph {
    fn new() -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(
            "local".into(),
            Node {
                id: "local".into(),
                label: "This Device".into(),
                ip: "local".into(),
                country: None,
                country_code: None,
                city: None,
                lat: None,
                lon: None,
                org: None,
                category: "local".into(),
                color: "#3b82f6".into(),
                bytes: 0,
                packets: 0,
                alerted: false,
                processes: HashMap::new(),
            },
        );
        Self {
            nodes,
            edges: HashMap::new(),
        }
    }
}

#[derive(Clone, Default, Serialize)]
struct TimelineBucket {
    minute: String,
    packets: u64,
    bytes: u64,
    alerts: u64,
}

#[derive(Default)]
struct EngineMetrics {
    matched_local: AtomicU64,
    attributed: AtomicU64,
    emitted_updates: AtomicU64,
    process_refreshes: AtomicU64,
}

#[derive(Clone)]
struct AppState {
    graph: Arc<RwLock<Graph>>,
    timeline: Arc<RwLock<BTreeMap<String, TimelineBucket>>>,
    capturing: Arc<AtomicBool>,
    port_filter: Arc<RwLock<HashSet<u16>>>,
    excluded_processes: Arc<RwLock<HashSet<String>>>,
    whitelisted_ips: Arc<RwLock<HashSet<String>>>,
    events: broadcast::Sender<Value>,
    process_snapshot: process::SharedSnapshot,
    capture_metrics: Arc<CaptureMetrics>,
    metrics: Arc<EngineMetrics>,
    adapters: Arc<RwLock<Vec<String>>>,
    started: Instant,
}

#[derive(Clone)]
struct PendingUpdate {
    node_id: String,
    edge_id: String,
    last_packet: RawPacket,
    direction: &'static str,
    process_name: Option<String>,
    bytes: u64,
    packet_count: u64,
}

#[derive(Deserialize)]
struct PortsBody {
    #[serde(default)]
    ports: Vec<u16>,
}

#[derive(Deserialize)]
struct ProcessesBody {
    #[serde(default)]
    excluded: Vec<String>,
}

#[derive(Deserialize)]
struct WhitelistBody {
    #[serde(default)]
    ips: Vec<String>,
}

#[derive(Deserialize)]
struct TimelineQuery {
    minutes: Option<i64>,
}

#[tokio::main]
async fn main() {
    let (events, _) = broadcast::channel::<Value>(4096);
    let (packet_tx, packet_rx) = mpsc::channel::<RawPacket>(32_768);

    let process_snapshot = process::new_shared_snapshot();
    if let Err(e) = process::refresh_now(&process_snapshot) {
        eprintln!("[process] initial refresh failed: {e}");
    }

    let capture_metrics = Arc::new(CaptureMetrics::default());
    let metrics = Arc::new(EngineMetrics::default());
    process::spawn_refresh(
        process_snapshot.clone(),
        Arc::new(AtomicU64Proxy(metrics.clone())),
    );

    let state = AppState {
        graph: Arc::new(RwLock::new(Graph::new())),
        timeline: Arc::new(RwLock::new(BTreeMap::new())),
        capturing: Arc::new(AtomicBool::new(true)),
        port_filter: Arc::new(RwLock::new(HashSet::new())),
        excluded_processes: Arc::new(RwLock::new(HashSet::new())),
        whitelisted_ips: Arc::new(RwLock::new(HashSet::new())),
        events,
        process_snapshot,
        capture_metrics,
        metrics,
        adapters: Arc::new(RwLock::new(Vec::new())),
        started: Instant::now(),
    };

    tokio::spawn(aggregate_loop(packet_rx, state.clone()));

    match capture::start_capture(
        packet_tx,
        state.capturing.clone(),
        state.capture_metrics.clone(),
    ) {
        Ok(adapters) => {
            println!("[capture] {} adapter(s) active", adapters.len());
            *state.adapters.write().await = adapters;
        }
        Err(e) => {
            eprintln!("[capture] disabled: {e}");
            state.capturing.store(false, Ordering::Relaxed);
        }
    }

    let app = Router::new()
        .route("/graph", get(get_graph))
        .route("/devices", get(get_devices))
        .route("/alerts", get(get_alerts))
        .route("/media", get(get_media))
        .route("/timeline", get(get_timeline))
        .route("/engine/stats", get(engine_stats))
        .route("/capture/status", get(capture_status))
        .route("/capture/start", post(capture_start))
        .route("/capture/stop", post(capture_stop))
        .route("/capture/ports", post(set_ports))
        .route("/capture/processes", post(set_processes))
        .route("/capture/whitelist", post(set_whitelist))
        .route("/ws", get(ws_handler))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8000));
    let listener = TcpListener::bind(addr)
        .await
        .expect("failed to bind 127.0.0.1:8000");
    println!("[orbis-engine] listening on http://{addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server failed");
}

// Small adapter letting the process refresh thread increment the metric without
// making process.rs depend on the whole EngineMetrics type.
struct AtomicU64Proxy(Arc<EngineMetrics>);

impl std::ops::Deref for AtomicU64Proxy {
    type Target = AtomicU64;
    fn deref(&self) -> &Self::Target {
        &self.0.process_refreshes
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn aggregate_loop(mut rx: mpsc::Receiver<RawPacket>, state: AppState) {
    let mut pending: HashMap<String, PendingUpdate> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            maybe = rx.recv() => {
                let Some(packet) = maybe else { break };
                handle_packet(packet, &state, &mut pending).await;
            }
            _ = tick.tick() => {
                flush_pending(&state, &mut pending).await;
            }
        }
    }
}

async fn handle_packet(
    packet: RawPacket,
    state: &AppState,
    pending: &mut HashMap<String, PendingUpdate>,
) {
    {
        let ports = state.port_filter.read().await;
        if !ports.is_empty()
            && !ports.contains(&packet.src_port)
            && !ports.contains(&packet.dst_port)
        {
            return;
        }
    }

    let Some(resolution) = process::resolve(
        &state.process_snapshot,
        packet.protocol,
        packet.src_ip,
        packet.src_port,
        packet.dst_ip,
        packet.dst_port,
    ) else {
        return;
    };
    state.metrics.matched_local.fetch_add(1, Ordering::Relaxed);

    if resolution.process.is_some() {
        state.metrics.attributed.fetch_add(1, Ordering::Relaxed);
    }

    let process_name = resolution
        .process
        .as_ref()
        .and_then(|p| p.name.clone());

    if let Some(name) = process_name.as_ref() {
        if state.excluded_processes.read().await.contains(name) {
            return;
        }
    }

    let remote_ip = if resolution.direction == "out" {
        packet.dst_ip
    } else {
        packet.src_ip
    };
    let remote = remote_ip.to_string();

    if state.whitelisted_ips.read().await.contains(&remote) {
        return;
    }

    let (label, category, color) = classify(packet.dst_port, packet.protocol);
    let node_id = remote.clone();
    let edge_id = format!("local-{node_id}-{}", packet.protocol);

    {
        let mut graph = state.graph.write().await;
        let node = graph.nodes.entry(node_id.clone()).or_insert_with(|| Node {
            id: node_id.clone(),
            label: remote.clone(),
            ip: remote.clone(),
            country: None,
            country_code: None,
            city: None,
            lat: None,
            lon: None,
            org: None,
            category: category.into(),
            color: color.into(),
            bytes: 0,
            packets: 0,
            alerted: false,
            processes: HashMap::new(),
        });

        node.bytes += packet.size as u64;
        node.packets += 1;
        if let Some(name) = process_name.as_ref() {
            let p = node.processes.entry(name.clone()).or_insert(ProcCounters {
                bytes: 0,
                packets: 0,
            });
            p.bytes += packet.size as u64;
            p.packets += 1;
        }

        let edge = graph.edges.entry(edge_id.clone()).or_insert_with(|| Edge {
            id: edge_id.clone(),
            source: "local".into(),
            target: node_id.clone(),
            protocol: packet.protocol.into(),
            label: label.into(),
            color: color.into(),
            bytes: 0,
            packets: 0,
        });
        edge.bytes += packet.size as u64;
        edge.packets += 1;
    }

    {
        let minute = Utc::now().format("%Y-%m-%dT%H:%M").to_string();
        let mut timeline = state.timeline.write().await;
        let bucket = timeline.entry(minute.clone()).or_insert(TimelineBucket {
            minute,
            packets: 0,
            bytes: 0,
            alerts: 0,
        });
        bucket.packets += 1;
        bucket.bytes += packet.size as u64;

        while timeline.len() > 1440 {
            let Some(first) = timeline.keys().next().cloned() else { break };
            timeline.remove(&first);
        }
    }

    let entry = pending.entry(edge_id.clone()).or_insert(PendingUpdate {
        node_id,
        edge_id,
        last_packet: packet.clone(),
        direction: resolution.direction,
        process_name: process_name.clone(),
        bytes: 0,
        packet_count: 0,
    });
    entry.last_packet = packet.clone();
    entry.direction = resolution.direction;
    entry.process_name = process_name;
    entry.bytes += packet.size as u64;
    entry.packet_count += 1;
}

async fn flush_pending(state: &AppState, pending: &mut HashMap<String, PendingUpdate>) {
    if pending.is_empty() {
        return;
    }

    let batch = std::mem::take(pending);
    let graph = state.graph.read().await;

    for (_, update) in batch {
        let (Some(node), Some(edge)) = (
            graph.nodes.get(&update.node_id),
            graph.edges.get(&update.edge_id),
        ) else {
            continue;
        };

        let msg = json!({
            "type": "update",
            "node": node,
            "edge": edge,
            "packet": {
                "src": update.last_packet.src_ip.to_string(),
                "dst": update.last_packet.dst_ip.to_string(),
                "protocol": update.last_packet.protocol,
                "size": update.bytes,
                "direction": update.direction,
                "process": update.process_name,
                "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                "packet_count": update.packet_count,
                "aggregated": true
            }
        });
        let _ = state.events.send(msg);
        state.metrics.emitted_updates.fetch_add(1, Ordering::Relaxed);
    }
}

fn classify(dst_port: u16, protocol: &str) -> (&'static str, &'static str, &'static str) {
    match dst_port {
        443 => ("HTTPS", "safe", "#22c55e"),
        80 => ("HTTP", "safe", "#84cc16"),
        53 => ("DNS", "dns", "#38bdf8"),
        22 => ("SSH", "admin", "#fb923c"),
        21 => ("FTP", "unknown", "#94a3b8"),
        25 => ("SMTP", "unknown", "#94a3b8"),
        3306 => ("MySQL", "unknown", "#94a3b8"),
        5432 => ("PostgreSQL", "unknown", "#94a3b8"),
        6379 => ("Redis", "unknown", "#94a3b8"),
        27017 => ("MongoDB", "unknown", "#94a3b8"),
        _ if protocol == "TCP" => ("TCP", "unknown", "#94a3b8"),
        _ => ("UDP", "unknown", "#94a3b8"),
    }
}

async fn get_graph(State(state): State<AppState>) -> Json<Value> {
    let graph = state.graph.read().await;
    Json(json!({
        "nodes": graph.nodes.values().cloned().collect::<Vec<_>>(),
        "edges": graph.edges.values().cloned().collect::<Vec<_>>()
    }))
}

async fn get_devices() -> Json<Value> {
    Json(json!({"devices": []}))
}

async fn get_alerts() -> Json<Value> {
    Json(json!({"alerts": []}))
}

async fn get_media() -> Json<Value> {
    Json(json!({"mic": [], "camera": []}))
}

async fn get_timeline(
    State(state): State<AppState>,
    Query(query): Query<TimelineQuery>,
) -> Json<Value> {
    let minutes = query.minutes.unwrap_or(60).clamp(1, 1440);
    let cutoff = (Utc::now() - ChronoDuration::minutes(minutes))
        .format("%Y-%m-%dT%H:%M")
        .to_string();

    let timeline = state.timeline.read().await;
    let rows: Vec<_> = timeline
        .range(cutoff..)
        .map(|(_, v)| v.clone())
        .collect();
    Json(json!({"timeline": rows}))
}

async fn engine_stats(State(state): State<AppState>) -> Json<Value> {
    let adapters = state.adapters.read().await.clone();
    let graph = state.graph.read().await;
    Json(json!({
        "engine": "rust-phase1",
        "uptime_ms": state.started.elapsed().as_millis(),
        "adapters": adapters,
        "capture_enabled": state.capturing.load(Ordering::Relaxed),
        "packets_seen": state.capture_metrics.packets_seen.load(Ordering::Relaxed),
        "packets_parsed": state.capture_metrics.packets_parsed.load(Ordering::Relaxed),
        "channel_drops": state.capture_metrics.channel_drops.load(Ordering::Relaxed),
        "matched_local_packets": state.metrics.matched_local.load(Ordering::Relaxed),
        "attributed_packets": state.metrics.attributed.load(Ordering::Relaxed),
        "emitted_updates": state.metrics.emitted_updates.load(Ordering::Relaxed),
        "process_table_refreshes": state.metrics.process_refreshes.load(Ordering::Relaxed),
        "process_table_entries": process::table_entries(&state.process_snapshot),
        "remote_nodes": graph.nodes.len().saturating_sub(1),
        "edges": graph.edges.len(),
        "aggregation_window_ms": 50,
        "process_table_refresh_ms": 500,
        "limitations": [
            "IPv4 TCP/UDP only",
            "timeline is in-memory in phase 1",
            "GeoIP/DNS enrichment remains Python-only",
            "anomaly detection remains Python-only",
            "LAN scanning remains Python-only",
            "media monitoring remains Python-only"
        ]
    }))
}

async fn capture_status(State(state): State<AppState>) -> Json<Value> {
    Json(status_value(&state).await)
}

async fn capture_start(State(state): State<AppState>) -> Json<Value> {
    state.capturing.store(true, Ordering::Relaxed);
    let msg = status_value(&state).await;
    let _ = state.events.send(json!({"type": "capture_status", "capturing": true,
        "ports": msg["ports"], "excluded_processes": msg["excluded_processes"],
        "whitelisted_ips": msg["whitelisted_ips"]}));
    Json(json!({"capturing": true}))
}

async fn capture_stop(State(state): State<AppState>) -> Json<Value> {
    state.capturing.store(false, Ordering::Relaxed);
    let msg = status_value(&state).await;
    let _ = state.events.send(json!({"type": "capture_status", "capturing": false,
        "ports": msg["ports"], "excluded_processes": msg["excluded_processes"],
        "whitelisted_ips": msg["whitelisted_ips"]}));
    Json(json!({"capturing": false}))
}

async fn set_ports(
    State(state): State<AppState>,
    Json(body): Json<PortsBody>,
) -> Json<Value> {
    let mut ports: Vec<u16> = body.ports.into_iter().filter(|p| *p > 0).collect();
    ports.sort_unstable();
    ports.dedup();

    {
        let mut filter = state.port_filter.write().await;
        *filter = ports.iter().copied().collect();
    }
    {
        let mut graph = state.graph.write().await;
        *graph = Graph::new();
    }

    let _ = state.events.send(json!({
        "type": "reset",
        "ports": ports,
        "nodes": [{
            "id": "local", "label": "This Device", "ip": "local",
            "country": null, "country_code": null, "city": null,
            "lat": null, "lon": null, "org": null,
            "category": "local", "color": "#3b82f6",
            "bytes": 0, "packets": 0, "alerted": false
        }],
        "edges": []
    }));

    Json(json!({"ports": ports}))
}

async fn set_processes(
    State(state): State<AppState>,
    Json(body): Json<ProcessesBody>,
) -> Json<Value> {
    let set: HashSet<String> = body.excluded.into_iter().collect();
    *state.excluded_processes.write().await = set;
    let msg = status_value(&state).await;
    let _ = state.events.send(json!({
        "type": "capture_status",
        "capturing": state.capturing.load(Ordering::Relaxed),
        "ports": msg["ports"],
        "excluded_processes": msg["excluded_processes"],
        "whitelisted_ips": msg["whitelisted_ips"]
    }));
    Json(json!({"excluded_processes": msg["excluded_processes"]}))
}

async fn set_whitelist(
    State(state): State<AppState>,
    Json(body): Json<WhitelistBody>,
) -> Json<Value> {
    let set: HashSet<String> = body.ips.into_iter().collect();
    *state.whitelisted_ips.write().await = set.clone();

    let mut removed = Vec::new();
    {
        let mut graph = state.graph.write().await;
        for ip in &set {
            if ip != "local" && graph.nodes.remove(ip).is_some() {
                removed.push(ip.clone());
            }
        }
        if !removed.is_empty() {
            let removed_set: HashSet<&str> = removed.iter().map(String::as_str).collect();
            graph.edges.retain(|_, edge| {
                !removed_set.contains(edge.source.as_str())
                    && !removed_set.contains(edge.target.as_str())
            });
        }
    }

    if !removed.is_empty() {
        let _ = state.events.send(json!({"type": "nodes_removed", "ids": removed}));
    }

    let msg = status_value(&state).await;
    let _ = state.events.send(json!({
        "type": "capture_status",
        "capturing": state.capturing.load(Ordering::Relaxed),
        "ports": msg["ports"],
        "excluded_processes": msg["excluded_processes"],
        "whitelisted_ips": msg["whitelisted_ips"]
    }));
    Json(json!({"whitelisted_ips": msg["whitelisted_ips"]}))
}

async fn status_value(state: &AppState) -> Value {
    let mut ports: Vec<u16> = state.port_filter.read().await.iter().copied().collect();
    let mut excluded: Vec<String> = state
        .excluded_processes
        .read()
        .await
        .iter()
        .cloned()
        .collect();
    let mut whitelist: Vec<String> = state
        .whitelisted_ips
        .read()
        .await
        .iter()
        .cloned()
        .collect();
    ports.sort_unstable();
    excluded.sort();
    whitelist.sort();

    json!({
        "capturing": state.capturing.load(Ordering::Relaxed),
        "ports": ports,
        "excluded_processes": excluded,
        "whitelisted_ips": whitelist
    })
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> Response {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(socket: WebSocket, state: AppState) {
    let mut rx = state.events.subscribe();
    let (mut sender, mut receiver) = socket.split();

    let graph = state.graph.read().await;
    let status = status_value(&state).await;
    let init = json!({
        "type": "init",
        "nodes": graph.nodes.values().cloned().collect::<Vec<_>>(),
        "edges": graph.edges.values().cloned().collect::<Vec<_>>(),
        "alerts": [],
        "media": {"mic": [], "camera": []},
        "capturing": status["capturing"],
        "ports": status["ports"],
        "excluded_processes": status["excluded_processes"],
        "whitelisted_ips": status["whitelisted_ips"]
    });
    drop(graph);

    if sender
        .send(Message::Text(init.to_string().into()))
        .await
        .is_err()
    {
        return;
    }

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Ok(value) => {
                        if sender.send(Message::Text(value.to_string().into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            incoming = receiver.next() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }
}
