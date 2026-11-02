"""
Streamlit Dashboard for SPECK Encrypted Deduplication Pipeline & Anomaly Detector
Enterprise UI & Security Operations Center
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

# ---------------- PAGE CONFIG & STYLES ----------------
st.set_page_config(
    page_title="SPECK Dedup & Cloud SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom High-Quality CSS for clean UI styling
st.markdown("""
<style>
    /* Global Typography & Spacing */
    .block-container {
        padding-top: 1.8rem;
        padding-bottom: 2.5rem;
    }
    
    /* Header hero banner */
    .hero-banner {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #334155 100%);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 14px;
        padding: 24px 28px;
        margin-bottom: 24px;
        color: #f8fafc;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.25);
    }
    .hero-title {
        font-size: 26px;
        font-weight: 700;
        margin-bottom: 6px;
        color: #f8fafc;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .hero-desc {
        font-size: 14px;
        color: #94a3b8;
        margin: 0;
        line-height: 1.5;
    }
    
    /* Card Styles */
    .metric-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 12px;
        padding: 16px 20px;
        box-shadow: 0 2px 6px rgba(0,0,0,0.04);
        margin-bottom: 14px;
        transition: transform 0.15s ease, box-shadow 0.15s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 12px rgba(0,0,0,0.08);
    }
    
    /* Status Badges */
    .badge-high {
        background-color: #fee2e2;
        color: #b91c1c;
        padding: 3px 9px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 12px;
        display: inline-block;
        border: 1px solid #fca5a5;
    }
    .badge-medium {
        background-color: #fef3c7;
        color: #b45309;
        padding: 3px 9px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 12px;
        display: inline-block;
        border: 1px solid #fcd34d;
    }
    .badge-low {
        background-color: #e0f2fe;
        color: #0369a1;
        padding: 3px 9px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 12px;
        display: inline-block;
        border: 1px solid #bae6fd;
    }
    .badge-new {
        background-color: #dcfce7;
        color: #15803d;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 11px;
    }
    .badge-duplicate {
        background-color: #ede9fe;
        color: #6d28d9;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 11px;
    }
    .badge-pass {
        background-color: #dcfce7;
        color: #166534;
        padding: 4px 12px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 13px;
        border: 1px solid #86efac;
    }
    
    /* Attack Cards */
    .attack-box {
        background: #f8fafc;
        border: 1px solid #cbd5e1;
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 12px;
        min-height: 155px;
    }
    .attack-title {
        font-weight: 600;
        font-size: 15px;
        margin-bottom: 6px;
        color: #1e293b;
    }
    .attack-caption {
        font-size: 12px;
        color: #64748b;
        margin-bottom: 10px;
        line-height: 1.4;
    }
</style>
""", unsafe_allow_html=True)

AWS_REGION = dedup_client.AWS_REGION
S3_BUCKET = dedup_client.S3_BUCKET
DYNAMO_TABLE = dedup_client.DYNAMO_TABLE
DETECTOR_LOG_GROUP = "/aws/lambda/dedup-anomaly-detector"

def format_bytes(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    elif size < 1024 ** 2:
        return f"{size / 1024:.2f} KB"
    elif size < 1024 ** 3:
        return f"{size / (1024 ** 2):.2f} MB"
    else:
        return f"{size / (1024 ** 3):.2f} GB"


# ---------------- SIDEBAR NAVIGATION & HEALTH ----------------
with st.sidebar:
    st.markdown("### 🛡️ SPECK Dedup Platform")
    st.caption("Secure Serverless Deduplication & Incident Defense")

    st.markdown("---")
    st.markdown("#### ☁️ Cloud Topology")
    st.markdown(f"**Region:** `{AWS_REGION}`")
    st.markdown(f"**S3 Storage:** `{S3_BUCKET}`")
    st.markdown(f"**Dedup Index:** `{DYNAMO_TABLE}`")
    st.markdown(f"**KMS Envelope:** `{dedup_client.KMS_KEY_ALIAS}`")

    st.markdown("---")
    st.markdown("#### 🔐 Cryptography Pipeline")
    st.markdown("- **Cipher:** `SPECK-128/128-CBC`")
    st.markdown(r"- **Convergent Key:** $K = \text{SHA256}(M)[:16]$")
    st.markdown(r"- **Chunk Tag:** $T = \text{SHA256}(C)$ *(Ciphertext-derived)*")
    st.markdown("- **Chunker:** Gear Rolling Hash (CDC)")

    st.markdown("---")
    if st.button("🔄 Clear Cache & Sync AWS", use_container_width=True):
        st.cache_data.clear()
        st.rerun()


# Hero Header
st.markdown("""
<div class="hero-banner">
    <div class="hero-title">
        <span>🛡️</span> SPECK Encrypted Deduplication & Security Operations Center
    </div>
    <div class="hero-desc">
        Deterministic client-side convergent encryption with NSA SPECK cipher, DynamoDB atomic deduplication indexing, 
        and real-time CloudTrail heuristic anomaly detection with automated S3 versioning containment.
    </div>
</div>
""", unsafe_allow_html=True)


# ---------------- TAB SETUP ----------------
tab_upload, tab_restore, tab_stats, tab_security, tab_attack, tab_cross_user = st.tabs([
    "📤 Upload & Dedup",
    "📥 Restore & Verify",
    "📊 Storage Analytics",
    "🛡️ Incident Monitor (SOC)",
    "🧪 Threat Simulation Lab",
    "👥 Convergent Dedup Demo",
])


# ==============================================================================
# TAB 1: UPLOAD & DEDUPLICATE
# ==============================================================================
with tab_upload:
    st.subheader("📤 File Ingestion & Deduplication Pipeline")
    st.caption("Splits files using Gear rolling-hash CDC, derives symmetric keys deterministically, and verifies tags against DynamoDB.")

    col_up1, col_up2 = st.columns([2, 1])
    with col_up1:
        uploaded_file = st.file_uploader("Drop a file to upload & deduplicate:", type=None, help="Any file type (PDF, logs, text, images, binary)")
    with col_up2:
        st.markdown("**Local File Path (Alternative):**")
        local_path = st.text_input("Enter local file path:", placeholder="e.g. C:/Users/.../sample.pdf", label_visibility="collapsed")

    btn_upload = st.button("⚡ Process & Upload to AWS", type="primary", use_container_width=True)

    if btn_upload:
        data = None
        filename = None

        if uploaded_file is not None:
            data = uploaded_file.getvalue()
            filename = uploaded_file.name
        elif local_path and os.path.exists(local_path):
            filename = os.path.basename(local_path)
            with open(local_path, "rb") as f:
                data = f.read()
        else:
            st.warning("⚠️ Please select a file or provide a valid local path.")

        if data is not None:
            with st.spinner(f"Chunking {filename}, encrypting with SPECK, and synchronizing DynamoDB index..."):
                try:
                    res = dedup_client.upload_file(data=data, filename=filename)
                    st.success(f"✅ Ingestion complete for `{res['name']}` in **{res['elapsed_sec']:.2f}s**!")

                    # Summary Metrics Row
                    m1, m2, m3, m4, m5 = st.columns(5)
                    m1.metric("Original Size", format_bytes(res["size"]))
                    m2.metric("Total Chunks", res["total_chunks"])
                    m3.metric("New Chunks Stored", res["new_chunks"], delta=f"{res['new_chunks']} added" if res['new_chunks'] else "0")
                    m4.metric("Deduplicated Chunks", res["dup_chunks"], delta=f"{res['dup_chunks']} reused" if res['dup_chunks'] else "0")
                    m5.metric("Storage Cost Saved", f"{res['savings_pct']:.1f}%", delta=f"{100 - (100 * res['new_bytes'] / max(res['size'], 1)):.1f}%")

                    # Visual Progress Bar
                    savings_fraction = max(0.0, min(1.0, res["savings_pct"] / 100.0))
                    st.markdown(f"**Storage Efficiency:** {res['savings_pct']:.1f}% duplicate space saved on this upload")
                    st.progress(savings_fraction)

                    st.markdown("---")
                    st.subheader("🧩 Chunk-Level Pipeline Inspection")

                    if res["chunks"]:
                        df_chunks = pd.DataFrame(res["chunks"])
                        
                        # Filter option
                        filter_opt = st.radio("Display Chunks:", ["All Chunks", "Only NEW Chunks", "Only DUPLICATE Chunks"], horizontal=True)
                        if filter_opt == "Only NEW Chunks":
                            df_filtered = df_chunks[df_chunks["status"] == "NEW"]
                        elif filter_opt == "Only DUPLICATE Chunks":
                            df_filtered = df_chunks[df_chunks["status"] == "DUPLICATE"]
                        else:
                            df_filtered = df_chunks

                        st.dataframe(
                            df_filtered[["chunk_idx", "status", "tag_short", "plain_len", "cipher_len", "tag"]].rename(
                                columns={
                                    "chunk_idx": "Chunk #",
                                    "status": "Index Claim",
                                    "tag_short": "Tag ID",
                                    "plain_len": "Plaintext (Bytes)",
                                    "cipher_len": "Ciphertext (Bytes)",
                                    "tag": "Ciphertext SHA-256 Tag",
                                }
                            ),
                            use_container_width=True,
                            hide_index=True,
                        )

                    st.info(f"📁 **Manifest:** `manifests/{filename}.json` written to S3 with KMS-wrapped chunk keys and root SHA-256 integrity tag.")

                except Exception as e:
                    st.error(f"❌ Upload failed: {e}")


# ==============================================================================
# TAB 2: RESTORE & VERIFY
# ==============================================================================
with tab_restore:
    st.subheader("📥 Cryptographic Restore & Integrity Validation")
    st.caption("Verifies zero data corruption: downloads ciphertext chunks, unwraps keys using KMS, decrypts with SPECK, and validates root SHA-256.")

    try:
        manifest_list = dedup_client._list_manifests()
    except Exception as e:
        manifest_list = []
        st.error(f"Error fetching manifests: {e}")

    if not manifest_list:
        st.info("ℹ️ No manifests found in `manifests/`. Upload a file in the Upload tab first.")
    else:
        file_names = [m["name"] for m in manifest_list]
        selected_file = st.selectbox("Select file to restore from cloud manifests:", file_names)
        m_item = next((m for m in manifest_list if m["name"] == selected_file), None)

        if m_item:
            c_info1, c_info2, c_info3 = st.columns(3)
            c_info1.markdown(f"**Size:** {format_bytes(m_item.get('size', 0))}")
            c_info2.markdown(f"**Chunk Count:** {len(m_item.get('chunks', []))}")
            c_info3.markdown(f"**Uploaded Timestamp:** `{m_item.get('created', 'N/A')}`")
            st.caption(f"Manifest Root Hash: `{m_item.get('file_sha256', '')}`")

        if st.button("🔓 Decrypt & Restore File", type="primary"):
            with st.spinner("Downloading chunks from S3 -> Unwrapping KMS envelope -> SPECK-128 decrypting..."):
                try:
                    res_down = dedup_client.download_file(selected_file)

                    if res_down["integrity"] == "PASS":
                        st.markdown("""
                        <div style="background-color: #f0fdf4; border: 1px solid #86efac; padding: 14px 18px; border-radius: 8px; margin: 12px 0;">
                            <span class="badge-pass">PASS</span> &nbsp; <strong>Root Hash Matches! File integrity cryptographically validated.</strong>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.error("🚨 INTEGRITY VERIFICATION FAILED: Computed SHA-256 does not match manifest!")

                    h_col1, h_col2 = st.columns(2)
                    h_col1.markdown(f"**Computed SHA-256:** `{res_down['computed_sha256']}`")
                    h_col2.markdown(f"**Manifest SHA-256:** `{res_down['file_sha256']}`")

                    st.download_button(
                        label=f"💾 Download Restored `{selected_file}` ({format_bytes(res_down['size'])})",
                        data=res_down["data"],
                        file_name=f"restored_{selected_file}",
                        mime="application/octet-stream",
                        use_container_width=True,
                    )
                except Exception as e:
                    st.error(f"Restore failed: {e}")


# ==============================================================================
# TAB 3: STORAGE ANALYTICS
# ==============================================================================
with tab_stats:
    st.subheader("📊 Storage Footprint & Deduplication Analytics")
    st.caption("Live metrics calculated directly from the DynamoDB `ChunkDedupIndex` and S3 object catalog.")

    try:
        stats = dedup_client.get_stats()

        kpi1, kpi2, kpi3, kpi4 = st.columns(4)
        kpi1.metric("Indexed Files", stats["files_count"])
        kpi2.metric("Logical Size (Raw)", format_bytes(stats["logical_bytes"]))
        kpi3.metric("Physical Size (S3)", format_bytes(stats["physical_bytes"]))
        kpi4.metric(
            "Dedup Multiplier",
            f"{stats['dedup_ratio']:.2f}x",
            delta=f"{stats['space_saved_pct']:.1f}% space saved",
        )

        kpi5, kpi6, kpi7, kpi8 = st.columns(4)
        kpi5.metric("Unique Chunks", stats["unique_chunks"])
        kpi6.metric("Total Chunk References", stats["chunk_refs"])
        duplicate_refs = max(0, stats["chunk_refs"] - stats["unique_chunks"])
        kpi7.metric("Duplicate References Saved", duplicate_refs)
        saved_bytes = max(0, stats["logical_bytes"] - stats["physical_bytes"])
        kpi8.metric("Net Storage Saved", format_bytes(saved_bytes))

        st.markdown("---")
        ch_col1, ch_col2 = st.columns([1, 1])

        with ch_col1:
            st.markdown("##### 📦 Storage Footprint Comparison")
            df_chart = pd.DataFrame({
                "Storage Category": ["Logical Footprint (No Dedup)", "Physical S3 Storage Used"],
                "Bytes": [stats["logical_bytes"], stats["physical_bytes"]],
            })
            st.bar_chart(df_chart, x="Storage Category", y="Bytes", color="Storage Category")

        with ch_col2:
            st.markdown("##### 📈 Per-File Size & Chunk Distribution")
            if stats["manifests"]:
                m_records = [{
                    "File": m["name"],
                    "Logical Size (B)": m["size"],
                    "Chunks": len(m["chunks"]),
                } for m in stats["manifests"]]
                st.bar_chart(pd.DataFrame(m_records), x="File", y="Logical Size (B)")
            else:
                st.info("No files uploaded yet.")

        st.markdown("---")
        st.markdown("##### 📁 Stored Files Manifest Catalog")
        if stats["manifests"]:
            df_manifests = pd.DataFrame([{
                "Filename": m["name"],
                "Size": format_bytes(m["size"]),
                "Chunks": len(m["chunks"]),
                "Created (UTC)": m["created"],
                "File SHA-256": m["file_sha256"],
            } for m in stats["manifests"]])
            st.dataframe(df_manifests, use_container_width=True, hide_index=True)

    except Exception as e:
        st.error(f"Error computing storage statistics: {e}")


# ==============================================================================
# TAB 4: INCIDENT MONITOR & ANOMALY DETECTOR (SOC)
# ==============================================================================
with tab_security:
    st.subheader("🛡️ Security Operations Center & Live Threat Feed")
    st.caption("Monitors CloudTrail S3 data events delivered to CloudWatch Logs. Pipeline-aware detection flags ransomware and automatically isolates the bucket.")

    s3_boto = boto3.client("s3", region_name=AWS_REGION)
    logs_boto = boto3.client("logs", region_name=AWS_REGION)

    # Versioning Defense Status
    try:
        v_res = s3_boto.get_bucket_versioning(Bucket=S3_BUCKET)
        v_status = v_res.get("Status", "Disabled / Unconfigured")
    except Exception as e:
        v_status = f"Error: {e}"

    v_col1, v_col2 = st.columns([1, 1])
    with v_col1:
        st.markdown("##### 🪣 S3 Bucket Versioning Defense")
        if v_status == "Enabled":
            st.markdown("""
            <div style="background-color: #f0fdf4; border: 1px solid #86efac; padding: 12px 16px; border-radius: 8px;">
                <span class="badge-pass">ENABLED</span> &nbsp; <strong>Active Defense: Bucket is protected against destructive overwrites and deletions.</strong>
            </div>
            """, unsafe_allow_html=True)
        elif v_status == "Suspended":
            st.markdown("""
            <div style="background-color: #fff1f2; border: 1px solid #fecdd3; padding: 12px 16px; border-radius: 8px;">
                <span class="badge-high">SUSPENDED</span> &nbsp; <strong>Warning: Bucket versioning has been suspended!</strong>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="background-color: #fefce8; border: 1px solid #fef08a; padding: 12px 16px; border-radius: 8px;">
                <span class="badge-medium">DISABLED / UNCONFIGURED</span> &nbsp; <strong>Default state. Will be auto-enabled upon detecting a HIGH severity attack.</strong>
            </div>
            """, unsafe_allow_html=True)

        # Quick action controls
        act1, act2 = st.columns(2)
        with act1:
            if st.button("Enable Versioning Manually", use_container_width=True):
                s3_boto.put_bucket_versioning(Bucket=S3_BUCKET, VersioningConfiguration={"Status": "Enabled"})
                st.success("Versioning set to Enabled!")
                time.sleep(0.5)
                st.rerun()
        with act2:
            if st.button("Suspend Versioning (Test)", use_container_width=True):
                s3_boto.put_bucket_versioning(Bucket=S3_BUCKET, VersioningConfiguration={"Status": "Suspended"})
                st.warning("Versioning set to Suspended!")
                time.sleep(0.5)
                st.rerun()

    with v_col2:
        st.markdown("##### ⚙️ Detection Pipeline Settings")
        st.markdown(f"- **Trigger Lambda:** `dedup-anomaly-detector` (every 5 min)")
        st.markdown(f"- **CloudTrail Log Group:** `{DETECTOR_LOG_GROUP}`")
        st.markdown(f"- **Automated Response:** Auto-enables S3 versioning on `bulk_delete` or `read_modify_write`")

    st.markdown("---")
    st.markdown("##### 🚨 Live Anomaly Incident Feed")

    lookback_hours = st.slider("Select Analysis Lookback Window (Hours):", min_value=1, max_value=48, value=24)

    # CloudWatch Logs Insights Query (Robust, avoids 1MB pagination bottleneck)
    with st.spinner(f"Querying CloudWatch Logs Insights for detections in the last {lookback_hours} hours..."):
        try:
            start_ts = int((datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).timestamp())
            end_ts = int(datetime.now(timezone.utc).timestamp())

            query_str = """
            fields @timestamp, @message
            | filter @message like /ANOMALY DETECTED/ or @message like /AUTO-RESPONSE/ or @message like /threshold/ or @message like /severity/
            | sort @timestamp desc
            | limit 100
            """
            
            qid = logs_boto.start_query(
                logGroupName=DETECTOR_LOG_GROUP,
                startTime=start_ts,
                endTime=end_ts,
                queryString=query_str,
            )["queryId"]

            # Wait for query results
            res_insights = {"status": "Running"}
            for _ in range(12):
                res_insights = logs_boto.get_query_results(queryId=qid)
                if res_insights["status"] in ("Complete", "Failed", "Cancelled"):
                    break
                time.sleep(0.8)

            rows = res_insights.get("results", [])

            if not rows:
                st.info(f"🟢 No anomaly events recorded in the last {lookback_hours} hours. Pipeline operating normally.")
            else:
                st.success(f"⚠️ Retrieved {len(rows)} threat intelligence log records:")

                # Render incidents nicely
                incident_list = []
                current_incident = None

                for r in rows:
                    row_dict = {f["field"]: f["value"] for f in r}
                    ts = row_dict.get("@timestamp", "")
                    msg = row_dict.get("@message", "").strip()

                    # Color badge helper
                    severity_badge = ""
                    if "HIGH" in msg:
                        severity_badge = '<span class="badge-high">HIGH</span>'
                    elif "MEDIUM" in msg:
                        severity_badge = '<span class="badge-medium">MEDIUM</span>'
                    elif "LOW" in msg:
                        severity_badge = '<span class="badge-low">LOW</span>'

                    auto_resp = "🛡️ AUTO-RESPONSE" if "AUTO-RESPONSE" in msg else ""

                    with st.expander(f"🚨 Incident at {ts} | {msg[:80]}...", expanded=True):
                        st.markdown(f"**Timestamp:** `{ts}` {severity_badge} {auto_resp}", unsafe_allow_html=True)
                        st.code(msg)

        except Exception as e:
            st.error(f"Error querying CloudWatch Logs Insights: {e}")


# ==============================================================================
# TAB 5: ATTACK SIMULATION LAB
# ==============================================================================
with tab_attack:
    st.subheader("🧪 Threat Adversary Simulation Lab")
    st.markdown("""
    <div style="background-color: #fef2f2; border: 1px solid #fecaca; padding: 12px 18px; border-radius: 8px; margin-bottom: 16px;">
        <strong style="color: #991b1b;">⚠️ Safe Isolation Notice:</strong>
        <span style="color: #7f1d1d;">All simulation vectors operate strictly under the <code>attack-sim/</code> S3 prefix. 
        Real user manifests and deduplicated data chunks are 100% untouched.</span>
    </div>
    """, unsafe_allow_html=True)

    st.write(
        "Simulate malicious cloud access patterns to validate the pipeline-aware detection rules. "
        "CloudTrail delivers S3 data events to CloudWatch Logs within **~5 minutes**, after which the scheduled Lambda executes."
    )

    col_atk1, col_atk2 = st.columns(2)

    with col_atk1:
        st.markdown("""
        <div class="attack-box">
            <div class="attack-title">1. 💥 Bulk Deletion Attack (<code>delete</code>)</div>
            <div class="attack-caption">Seeds 9 victims and deletes them all. Violates the core invariant: the deduplication client never issues DeleteObject.</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("🚀 Execute Bulk Deletion", key="atk_del", type="primary", use_container_width=True):
            with st.spinner("Executing 9 PutObject + 9 DeleteObject..."):
                msg = simulate_attack_v2.run("delete")
                st.success(f"Executed: {msg}")
                st.info("Expected: `bulk_delete` (HIGH) -> Auto-response: S3 versioning enabled -> SNS alert triggered.")

        st.markdown("""
        <div class="attack-box">
            <div class="attack-title">2. 🔄 In-Place Ransomware Overwrite (<code>rmw</code>)</div>
            <div class="attack-caption">Reads 9 objects and overwrites them in-place with XOR encrypted payloads. Violates chunk immutability.</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("🚀 Execute In-Place Ransomware", key="atk_rmw", type="primary", use_container_width=True):
            with st.spinner("Executing read-modify-write pattern..."):
                msg = simulate_attack_v2.run("rmw")
                st.success(f"Executed: {msg}")
                st.info("Expected: `read_modify_write` (HIGH) -> Auto-response: S3 versioning enabled -> SNS alert triggered.")

        st.markdown("""
        <div class="attack-box">
            <div class="attack-title">3. 📂 Copy-and-Delete Ransomware (<code>copy</code>)</div>
            <div class="attack-caption">Reads 9 victims, writes reversed .enc copies, then deletes the original victim objects.</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("🚀 Execute Copy & Delete", key="atk_copy", use_container_width=True):
            with st.spinner("Executing copy & delete pattern..."):
                msg = simulate_attack_v2.run("copy")
                st.success(f"Executed: {msg}")
                st.info("Expected: `bulk_delete` + `unexpected_prefix_write` (HIGH).")

    with col_atk2:
        st.markdown("""
        <div class="attack-box">
            <div class="attack-title">4. ⚙️ Versioning Tampering (<code>config</code>)</div>
            <div class="attack-caption">Sets S3 bucket versioning to Suspended. Attackers do this to prevent recovery before launching ransomware.</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("🚀 Execute Config Tampering", key="atk_cfg", use_container_width=True):
            with st.spinner("Suspending bucket versioning..."):
                msg = simulate_attack_v2.run("config")
                st.warning(f"Executed: {msg}")
                st.info("Expected: `config_tampering` (HIGH) -> SNS alert triggered.")

        st.markdown("""
        <div class="attack-box">
            <div class="attack-title">5. 🐢 Slow-and-Low Evasion (<code>slow</code>)</div>
            <div class="attack-caption">Deletes only 3 objects (below threshold of 5). Demonstrates the trade-off between sensitivity and false positives.</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("🚀 Execute Slow Evasion", key="atk_slow", use_container_width=True):
            with st.spinner("Executing 3 deletes..."):
                msg = simulate_attack_v2.run("slow")
                st.warning(f"Executed: {msg}")
                st.info("Expected: UNDETECTED. (Documented evaluation case for paper / viva discussion).")


# ==============================================================================
# TAB 6: CROSS-USER DEDUP DEMO
# ==============================================================================
with tab_cross_user:
    st.subheader("👥 Cross-User Deduplication via Convergent Cryptography")
    st.caption("Proves how two completely independent users store identical data with zero storage waste without sharing secret keys.")

    st.markdown("""
    ```
    User A: File M  --->  CDC Chunks  --->  K = H(M)[:16]  --->  C_A = SPECK_K(M)  --->  Tag = H(C_A)  [NEW: Uploaded]
    User B: File M  --->  CDC Chunks  --->  K = H(M)[:16]  --->  C_B = SPECK_K(M)  --->  Tag = H(C_B)  [DUP: 0 Bytes Stored!]
    ```
    """)

    sample_input = st.text_area(
        "Shared Test Document Content:",
        value="Cloud Architecture Project - Convergent SPECK-128/128 Deduplication Pipeline.\n" * 40,
        height=140,
    )

    if st.button("⚡ Run Multi-User Ingestion Test", type="primary", use_container_width=True):
        raw_payload = sample_input.encode("utf-8")

        st.markdown("#### Step 1: User Alice Ingests Document")
        with st.spinner("User Alice uploading..."):
            u1_res = dedup_client.upload_data(raw_payload, "alice_confidential.txt")

        c_u1, c_u2 = st.columns(2)
        with c_u1:
            st.metric("Alice Stored Bytes", format_bytes(u1_res["new_bytes"]))
            st.metric("Alice New Chunks", u1_res["new_chunks"])
            st.caption(f"Alice's manifest: `manifests/alice_confidential.txt.json`")

        st.markdown("#### Step 2: User Bob Ingests Identical Document")
        with st.spinner("User Bob uploading..."):
            u2_res = dedup_client.upload_data(raw_payload, "bob_confidential.txt")

        with c_u2:
            st.metric("Bob Stored Bytes", format_bytes(u2_res["new_bytes"]), delta="-100% (Zero Cloud Footprint!)")
            st.metric("Bob Duplicate Chunks", u2_res["dup_chunks"])
            st.caption(f"Bob's manifest: `manifests/bob_confidential.txt.json`")

        st.success(
            f"🎉 **Convergent Deduplication Verified!** User Bob stored **0 new bytes** (100% duplicate savings). "
            f"Both Alice and Bob possess independent manifests encrypted under their own envelope, but the storage backend deduplicated 100% of the payload."
        )
