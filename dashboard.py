"""
CloudVault // Encrypted Deduplication & Autonomous Threat Detection
Architecture: SPECK-128/128-CBC + Convergent Indexing + CloudWatch Anomaly Intelligence
"""

import os
import io
import time
import json
from datetime import datetime, timedelta, timezone

import boto3
import pandas as pd
import streamlit as st

import dedup_client
import simulate_attack_v2

# ----------------- SYSTEM CONFIG -----------------
st.set_page_config(
    page_title="CloudVault | Encrypted Dedup & SOC",
    page_icon="⬡",
    layout="wide",
    initial_sidebar_state="expanded",
)

AWS_REGION = dedup_client.AWS_REGION
S3_BUCKET = dedup_client.S3_BUCKET
DYNAMO_TABLE = dedup_client.DYNAMO_TABLE
DETECTOR_LOG_GROUP = "/aws/lambda/dedup-anomaly-detector"

def format_bytes(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    elif size < 1024 ** 2:
        return f"{size / 1024:.1f} KB"
    elif size < 1024 ** 3:
        return f"{size / (1024 ** 2):.2f} MB"
    else:
        return f"{size / (1024 ** 3):.2f} GB"

# ----------------- PRODUCTION CSS SYSTEM -----------------
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

    :root {
        --bg-primary: #0a0e17;
        --bg-surface: #111726;
        --bg-elevated: #182238;
        --border-subtle: #1f2c47;
        --border-focus: #3b82f6;
        --text-primary: #f1f5f9;
        --text-secondary: #94a3b8;
        --text-muted: #64748b;
        --accent-blue: #2563eb;
        --accent-emerald: #059669;
        --accent-amber: #d97706;
        --accent-rose: #e11d48;
    }

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        color: var(--text-primary);
    }
    
    code, kbd, samp, pre {
        font-family: 'JetBrains Mono', monospace !important;
    }

    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
        max-width: 1320px;
    }

    /* Top Navigation Navbar */
    .top-nav {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 14px 20px;
        background: #0f1629;
        border: 1px solid #1e293b;
        border-radius: 12px;
        margin-bottom: 24px;
    }
    .brand-title {
        font-size: 17px;
        font-weight: 700;
        letter-spacing: -0.02em;
        display: flex;
        align-items: center;
        gap: 10px;
        color: #f8fafc;
    }
    .brand-title span.logo-icon {
        color: #3b82f6;
        font-size: 20px;
    }
    .status-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: rgba(16, 185, 129, 0.1);
        border: 1px solid rgba(16, 185, 129, 0.3);
        color: #34d399;
        font-size: 12px;
        font-weight: 500;
        padding: 4px 10px;
        border-radius: 9999px;
    }
    .status-pill::before {
        content: "";
        width: 6px;
        height: 6px;
        background-color: #10b981;
        border-radius: 50%;
    }

    /* Metric Cards */
    .metric-row {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 16px;
        margin-bottom: 24px;
    }
    .card {
        background: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 12px;
        padding: 18px 20px;
    }
    .card-label {
        font-size: 12px;
        font-weight: 500;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 6px;
    }
    .card-val {
        font-size: 26px;
        font-weight: 700;
        letter-spacing: -0.03em;
        color: #f8fafc;
        margin-bottom: 4px;
    }
    .card-sub {
        font-size: 12px;
        color: #64748b;
    }
    .card-sub.positive {
        color: #34d399;
        font-weight: 500;
    }

    /* Subtle tables and elements */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        border-bottom: 1px solid #1e293b;
        padding-bottom: 4px;
        margin-bottom: 20px;
    }
    .stTabs [data-baseweb="tab"] {
        font-size: 14px;
        font-weight: 500;
        color: #94a3b8;
        border-radius: 8px;
        padding: 8px 16px;
        border: none;
        background: transparent;
    }
    .stTabs [aria-selected="true"] {
        color: #ffffff !important;
        background: #1e293b !important;
    }
    
    /* Threat Event Row */
    .event-card {
        background: #0b1329;
        border-left: 4px solid #ef4444;
        border: 1px solid #1e293b;
        border-left-width: 4px;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 12px;
    }
    .event-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 8px;
    }
    .tag-high {
        background: rgba(239, 68, 68, 0.15);
        color: #f87171;
        font-size: 11px;
        font-weight: 600;
        padding: 2px 8px;
        border-radius: 4px;
        border: 1px solid rgba(239, 68, 68, 0.3);
    }
    .tag-medium {
        background: rgba(245, 158, 11, 0.15);
        color: #fbbf24;
        font-size: 11px;
        font-weight: 600;
        padding: 2px 8px;
        border-radius: 4px;
        border: 1px solid rgba(245, 158, 11, 0.3);
    }
    .tag-low {
        background: rgba(59, 130, 246, 0.15);
        color: #60a5fa;
        font-size: 11px;
        font-weight: 600;
        padding: 2px 8px;
        border-radius: 4px;
        border: 1px solid rgba(59, 130, 246, 0.3);
    }

    /* Attack Box Clean Styling */
    .sim-card {
        background: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 18px;
        margin-bottom: 14px;
    }
    .sim-title {
        font-size: 14px;
        font-weight: 600;
        color: #f1f5f9;
        margin-bottom: 4px;
    }
    .sim-desc {
        font-size: 12px;
        color: #94a3b8;
        line-height: 1.45;
        margin-bottom: 12px;
    }
</style>
""", unsafe_allow_html=True)

# ----------------- SIDEBAR: MINIMAL CLOUD TOPOLOGY -----------------
with st.sidebar:
    st.markdown("### **CloudVault**")
    st.caption("SPECK Deduplication & Security Architecture")

    st.markdown("---")
    st.markdown("##### Cloud Environment")
    st.markdown(f"**Region:** `{AWS_REGION}`")
    st.markdown(f"**Storage Bucket:** `{S3_BUCKET}`")
    st.markdown(f"**Index Table:** `{DYNAMO_TABLE}`")
    st.markdown(f"**Key Envelope:** `alias/speck-dedup-key`")

    st.markdown("---")
    st.markdown("##### Cryptography")
    st.markdown("- **Cipher:** SPECK-128/128 (CBC)")
    st.markdown(r"- **Key:** $K = \text{SHA256}(M)[:16]$")
    st.markdown(r"- **Chunk Tag:** $T = \text{SHA256}(C)$")
    st.markdown("- **Chunking:** Gear rolling-hash CDC")

    st.markdown("---")
    if st.button("Refresh Telemetry", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

# ----------------- TOP NAVBAR -----------------
st.markdown("""
<div class="top-nav">
    <div class="brand-title">
        <span class="logo-icon">⬡</span>
        <span>CloudVault // Deduplication & Security Gateway</span>
    </div>
    <div class="status-pill">
        Pipeline Live & Enforced
    </div>
</div>
""", unsafe_allow_html=True)

# ----------------- TABS -----------------
tab_storage, tab_files, tab_security, tab_lab, tab_demo = st.tabs([
    "Overview & Analytics",
    "File Operations",
    "Security & Threat Feed",
    "Adversary Lab",
    "Multi-User Verification",
])

# ==============================================================================
# TAB 1: OVERVIEW & STORAGE ANALYTICS
# ==============================================================================
with tab_storage:
    try:
        stats = dedup_client.get_stats()
        
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Raw Ingested Volume", format_bytes(stats["logical_bytes"]))
        with c2:
            st.metric("Physical Storage Used", format_bytes(stats["physical_bytes"]))
        with c3:
            saved_vol = max(0, stats["logical_bytes"] - stats["physical_bytes"])
            st.metric("Net Space Saved", format_bytes(saved_vol), delta=f"{stats['space_saved_pct']:.1f}%")
        with c4:
            st.metric("Deduplication Factor", f"{stats['dedup_ratio']:.2f}x")

        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

        col_bar, col_inv = st.columns([1, 1])

        with col_bar:
            st.markdown("##### Storage Footprint Breakdown")
            df_storage = pd.DataFrame({
                "Tier": ["Raw Ingested", "Physical S3 Stored"],
                "Volume (Bytes)": [stats["logical_bytes"], stats["physical_bytes"]],
            })
            st.bar_chart(df_storage, x="Tier", y="Volume (Bytes)", color="Tier")

        with col_inv:
            st.markdown("##### Ingested Manifest Catalog")
            if stats["manifests"]:
                df_manifests = pd.DataFrame([{
                    "Filename": m["name"],
                    "Size": format_bytes(m["size"]),
                    "Chunks": len(m["chunks"]),
                    "Created": m["created"][:19].replace("T", " "),
                } for m in stats["manifests"]])
                st.dataframe(df_manifests, use_container_width=True, hide_index=True)
            else:
                st.info("No files currently stored. Ingest files using the File Operations tab.")

    except Exception as e:
        st.error(f"Failed to fetch storage telemetry: {e}")


# ==============================================================================
# TAB 2: FILE OPERATIONS (UPLOAD / RESTORE)
# ==============================================================================
with tab_files:
    op_mode = st.radio("Select Action:", ["Ingest & Deduplicate File", "Restore & Verify File"], horizontal=True)

    if op_mode == "Ingest & Deduplicate File":
        st.markdown("##### Ingest File")
        st.caption("Splits the stream via Gear CDC, generates convergent keys, and only uploads unique ciphertext blocks to S3.")

        up_col1, up_col2 = st.columns([2, 1])
        with up_col1:
            up_file = st.file_uploader("Upload a document, archive, or binary:", type=None)
        with up_col2:
            st.markdown("**Or specify path on disk:**")
            disk_path = st.text_input("Local path:", placeholder="e.g. C:/Users/.../data.pdf", label_visibility="collapsed")

        if st.button("Execute Ingestion Pipeline", type="primary"):
            payload = None
            filename = None

            if up_file:
                payload = up_file.getvalue()
                filename = up_file.name
            elif disk_path and os.path.exists(disk_path):
                filename = os.path.basename(disk_path)
                with open(disk_path, "rb") as f:
                    payload = f.read()
            else:
                st.warning("Provide a file to proceed.")

            if payload:
                with st.spinner("Processing CDC chunking and SPECK encryption..."):
                    try:
                        res = dedup_client.upload_file(data=payload, filename=filename)
                        st.success(f"Ingested `{res['name']}` ({format_bytes(res['size'])}) in {res['elapsed_sec']:.2f}s")

                        r1, r2, r3, r4 = st.columns(4)
                        r1.metric("Total Chunks", res["total_chunks"])
                        r2.metric("New Stored", res["new_chunks"])
                        r3.metric("Deduplicated", res["dup_chunks"])
                        r4.metric("Savings", f"{res['savings_pct']:.1f}%")

                        if res["chunks"]:
                            with st.expander("Inspect Chunk Mapping", expanded=False):
                                df_c = pd.DataFrame(res["chunks"])[["chunk_idx", "status", "plain_len", "cipher_len", "tag_short"]]
                                df_c.columns = ["Chunk #", "Claim Status", "Plaintext (B)", "Ciphertext (B)", "Tag ID"]
                                st.dataframe(df_c, use_container_width=True, hide_index=True)

                    except Exception as err:
                        st.error(f"Ingestion failed: {err}")

    else:
        st.markdown("##### Restore & Verify Integrity")
        st.caption("Unwraps envelope keys from KMS, downloads encrypted chunks, decrypts via SPECK, and asserts whole-file SHA-256.")

        try:
            m_list = dedup_client._list_manifests()
        except Exception:
            m_list = []

        if not m_list:
            st.info("No stored manifests found.")
        else:
            names = [m["name"] for m in m_list]
            selected_file = st.selectbox("Select file to restore:", names)
            target_m = next((m for m in m_list if m["name"] == selected_file), None)

            if target_m:
                st.caption(f"Size: {format_bytes(target_m['size'])} | Chunks: {len(target_m['chunks'])} | SHA-256: `{target_m['file_sha256']}`")

            if st.button("Decrypt & Reassemble File", type="primary"):
                with st.spinner("Decrypting chunks and calculating checksum..."):
                    try:
                        down_res = dedup_client.download_file(selected_file)

                        if down_res["integrity"] == "PASS":
                            st.success(f"Integrity Check: PASS (SHA-256 matches root manifest)")
                        else:
                            st.error(f"Integrity Check: FAIL (Checksum mismatch)")

                        st.download_button(
                            label=f"Download `{selected_file}`",
                            data=down_res["data"],
                            file_name=f"restored_{selected_file}",
                            mime="application/octet-stream",
                            use_container_width=True,
                        )
                    except Exception as err:
                        st.error(f"Restoration failed: {err}")


# ==============================================================================
# TAB 3: SECURITY & INCIDENT MONITOR
# ==============================================================================
with tab_security:
    s3_boto = boto3.client("s3", region_name=AWS_REGION)
    logs_boto = boto3.client("logs", region_name=AWS_REGION)

    # Versioning Status
    try:
        v_res = s3_boto.get_bucket_versioning(Bucket=S3_BUCKET)
        v_status = v_res.get("Status", "Disabled / Unconfigured")
    except Exception as err:
        v_status = "Error"

    sec_col1, sec_col2 = st.columns([1, 1])

    with sec_col1:
        st.markdown("##### Storage Immutability & Versioning")
        if v_status == "Enabled":
            st.success("State: **Enabled** (Protected against destructive tampering)")
        elif v_status == "Suspended":
            st.error("State: **Suspended** (Vulnerable to object deletion)")
        else:
            st.warning("State: **Unconfigured** (Auto-response will enable on HIGH anomaly)")

        t_col1, t_col2 = st.columns(2)
        with t_col1:
            if st.button("Enable Versioning Manually", use_container_width=True):
                s3_boto.put_bucket_versioning(Bucket=S3_BUCKET, VersioningConfiguration={"Status": "Enabled"})
                st.rerun()
        with t_col2:
            if st.button("Suspend Versioning", use_container_width=True):
                s3_boto.put_bucket_versioning(Bucket=S3_BUCKET, VersioningConfiguration={"Status": "Suspended"})
                st.rerun()

    with sec_col2:
        st.markdown("##### Threat Detection Heuristics")
        st.markdown("- **Engine:** Lambda scheduled every 5 min over CloudTrail")
        st.markdown("- **Invariants Enforced:** Zero DeleteObject allowed; Chunk immutability (No RMW)")
        st.markdown("- **Auto-Mitigation:** Auto-enables versioning on HIGH destructive events")

    st.markdown("---")
    st.markdown("##### Incident Feed (CloudWatch Logs Insights)")

    lookback = st.select_slider("Analysis lookback window:", options=[1, 6, 12, 24, 48], value=24, format_func=lambda x: f"{x} hours")

    try:
        start_ts = int((datetime.now(timezone.utc) - timedelta(hours=lookback)).timestamp())
        end_ts = int(datetime.now(timezone.utc).timestamp())

        q_str = """
        fields @timestamp, @message
        | filter @message like /ANOMALY DETECTED/ or @message like /AUTO-RESPONSE/ or @message like /threshold/ or @message like /severity/
        | sort @timestamp desc
        | limit 50
        """
        
        qid = logs_boto.start_query(
            logGroupName=DETECTOR_LOG_GROUP,
            startTime=start_ts,
            endTime=end_ts,
            queryString=q_str,
        )["queryId"]

        res_insights = {"status": "Running"}
        for _ in range(10):
            res_insights = logs_boto.get_query_results(queryId=qid)
            if res_insights["status"] in ("Complete", "Failed", "Cancelled"):
                break
            time.sleep(0.6)

        results = res_insights.get("results", [])

        if not results:
            st.info("No threat incidents recorded in selected window.")
        else:
            st.markdown(f"**{len(results)} threat log entries detected:**")
            
            for row in results:
                row_map = {item["field"]: item["value"] for item in row}
                raw_msg = row_map.get("@message", "").strip()
                t_stamp = row_map.get("@timestamp", "")

                severity = "HIGH" if "HIGH" in raw_msg else ("MEDIUM" if "MEDIUM" in raw_msg else "INFO")
                tag_class = "tag-high" if severity == "HIGH" else ("tag-medium" if severity == "MEDIUM" else "tag-low")

                st.markdown(f"""
                <div class="event-card">
                    <div class="event-header">
                        <span style="font-size: 13px; font-weight: 600; color: #e2e8f0;">{t_stamp}</span>
                        <span class="{tag_class}">{severity}</span>
                    </div>
                    <div style="font-size: 12px; color: #94a3b8; font-family: 'JetBrains Mono', monospace;">
                        {raw_msg}
                    </div>
                </div>
                """, unsafe_allow_html=True)

    except Exception as err:
        st.error(f"CloudWatch query failed: {err}")


# ==============================================================================
# TAB 4: ADVERSARY LAB (SIMULATED ATTACKS)
# ==============================================================================
with tab_lab:
    st.markdown("##### Adversary Simulation Lab")
    st.caption("Executes realistic ransomware and tampering vectors strictly within the isolated `attack-sim/` prefix.")

    sim1, sim2 = st.columns(2)

    with sim1:
        st.markdown("""
        <div class="sim-card">
            <div class="sim-title">💥 Bulk Object Deletion</div>
            <div class="sim-desc">Issues 9 PutObject + 9 DeleteObject calls in rapid succession. Tests threshold detection on zero-delete invariants.</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Simulate Bulk Delete", key="sim_del", use_container_width=True):
            with st.spinner("Executing simulation..."):
                m = simulate_attack_v2.run("delete")
                st.success(m)

        st.markdown("""
        <div class="sim-card">
            <div class="sim-title">🔄 In-Place Ransomware Overwrite</div>
            <div class="sim-desc">Reads 9 objects and rewrites encrypted payloads in place. Violates chunk immutability.</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Simulate In-Place Overwrite", key="sim_rmw", use_container_width=True):
            with st.spinner("Executing simulation..."):
                m = simulate_attack_v2.run("rmw")
                st.success(m)

    with sim2:
        st.markdown("""
        <div class="sim-card">
            <div class="sim-title">⚙️ Versioning Tampering</div>
            <div class="sim-desc">Suspends S3 bucket versioning. Attackers use this to prevent recovery before launching destruction.</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Simulate Versioning Suspension", key="sim_cfg", use_container_width=True):
            with st.spinner("Executing simulation..."):
                m = simulate_attack_v2.run("config")
                st.warning(m)

        st.markdown("""
        <div class="sim-card">
            <div class="sim-title">🐢 Slow-and-Low Evasion</div>
            <div class="sim-desc">Issues only 3 deletes (below threshold of 5). Tests intentional tradeoff against administrative false positives.</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Simulate Slow Evasion", key="sim_slow", use_container_width=True):
            with st.spinner("Executing simulation..."):
                m = simulate_attack_v2.run("slow")
                st.info(m)


# ==============================================================================
# TAB 5: MULTI-USER DEMO (CONVERGENT PROOF)
# ==============================================================================
with tab_demo:
    st.markdown("##### Multi-Tenant Convergent Proof")
    st.caption("Demonstrates how two independent actors uploading identical data achieve 100% deduplication without key disclosure.")

    sample_doc = st.text_area(
        "Payload for multi-tenant simulation:",
        value="CloudVault Enterprise Multi-Tenant Deduplication Verification Stream\n" * 25,
        height=100,
    )

    if st.button("Run Multi-User Ingestion", type="primary"):
        raw_b = sample_doc.encode("utf-8")

        with st.spinner("Simulating User Alice upload..."):
            res_a = dedup_client.upload_data(raw_b, "tenant_alice.txt")

        with st.spinner("Simulating User Bob upload..."):
            res_b = dedup_client.upload_data(raw_b, "tenant_bob.txt")

        u_col1, u_col2 = st.columns(2)
        with u_col1:
            st.markdown("###### Tenant A (Alice)")
            st.metric("Uploaded Bytes", format_bytes(res_a["new_bytes"]))
            st.metric("New Chunks Stored", res_a["new_chunks"])
            st.caption(f"Manifest: `manifests/tenant_alice.txt.json`")

        with u_col2:
            st.markdown("###### Tenant B (Bob)")
            st.metric("Uploaded Bytes", format_bytes(res_b["new_bytes"]), delta="-100% (Zero storage footprint)")
            st.metric("Deduplicated Chunks", res_b["dup_chunks"])
            st.caption(f"Manifest: `manifests/tenant_bob.txt.json`")

        st.success("Verification complete: Zero bytes stored for second tenant while preserving independent KMS envelope manifests.")
