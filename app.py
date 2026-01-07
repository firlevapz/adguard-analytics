import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# Page config
st.set_page_config(
    page_title="AdGuard DNS Analytics",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ AdGuard DNS Analytics")


@st.cache_data(ttl="5m")
def load_querylog() -> pd.DataFrame:
    """Load query log from JSON file (newline-delimited JSON)."""
    querylog_path = Path("data/querylog.json")
    records = []
    with open(querylog_path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    df = pd.DataFrame(records)
    # Parse timestamp
    df["T"] = pd.to_datetime(df["T"])
    return df


@st.cache_data(ttl="1h")
def load_leases() -> dict[str, str]:
    """Load leases and return IP to hostname mapping."""
    leases_path = Path("data/leases.json")
    with open(leases_path) as f:
        data = json.load(f)

    ip_to_hostname = {}
    for lease in data.get("leases", []):
        ip = lease.get("ip", "")
        hostname = lease.get("hostname", "")
        if ip and hostname:
            ip_to_hostname[ip] = hostname
    return ip_to_hostname


def extract_top_level_domain(host: str) -> str:
    """Extract top-level domain from a hostname, ignoring subdomains.

    Examples:
        www.google.com -> google.com
        accounts.google.com -> google.com
        staticcdn.duckduckgo.com -> duckduckgo.com
        www.willhaben.at -> willhaben.at
    """
    if not host:
        return ""

    parts = host.lower().split(".")

    # Handle special cases for common TLDs
    if len(parts) >= 2:
        # Check for multi-part TLDs like co.uk, com.au, etc.
        multi_part_tlds = {
            "co.uk",
            "com.au",
            "co.nz",
            "co.jp",
            "com.br",
            "org.uk",
            "net.au",
            "ac.uk",
            "gov.uk",
            "3gppnetwork.org",
        }

        if len(parts) >= 3:
            potential_multi_tld = f"{parts[-2]}.{parts[-1]}"
            if potential_multi_tld in multi_part_tlds:
                if len(parts) >= 3:
                    return f"{parts[-3]}.{parts[-2]}.{parts[-1]}"

        # Standard case: return last two parts
        return f"{parts[-2]}.{parts[-1]}"

    return host


def get_filter_reason(result: dict | None) -> str:
    """Extract filter reason from result."""
    if not result or not isinstance(result, dict):
        return "Not Filtered"

    reason_codes = {
        0: "Not Filtered",
        1: "Blocked by Filter",
        2: "Blocked (Safebrowsing)",
        3: "Blocked by Rule",
        4: "Blocked (Parental)",
        5: "Rewritten",
        6: "Rewritten (Hosts)",
        7: "Rewritten (Safe Search)",
    }

    reason = result.get("Reason", 0)
    return reason_codes.get(reason, f"Unknown ({reason})")


# Load data
try:
    df = load_querylog()
    ip_to_hostname = load_leases()
except FileNotFoundError as e:
    st.error(f"Error loading data: {e}")
    st.stop()

# Process data
df["hostname"] = df["IP"].map(lambda ip: ip_to_hostname.get(ip, ip))
df["top_level_domain"] = df["QH"].apply(extract_top_level_domain)
df["filter_status"] = df["Result"].apply(get_filter_reason)
df["is_filtered"] = df["Result"].apply(
    lambda x: x.get("IsFiltered", False) if isinstance(x, dict) else False
)
df["is_cached"] = df.get("Cached", False)

# Sidebar filters
st.sidebar.header("🔍 Filters")

# Quick time range selector
st.sidebar.subheader("⏱️ Time Range")
time_range = st.sidebar.radio(
    "Quick Select",
    options=["Last 24 Hours", "Last Week", "Last Month", "Custom"],
    index=0,  # Default to "Last 24 Hours"
    horizontal=True,
)

# Calculate time ranges using timezone-aware datetime (UTC)
now = datetime.now(timezone.utc)
if time_range == "Last 24 Hours":
    start_time = now - timedelta(hours=24)
    df = df[df["T"] >= start_time]
elif time_range == "Last Week":
    start_time = now - timedelta(days=7)
    df = df[df["T"] >= start_time]
elif time_range == "Last Month":
    start_time = now - timedelta(days=30)
    df = df[df["T"] >= start_time]
elif time_range == "Custom" and len(df) > 0:
    # Custom date range filter
    min_date = df["T"].min().date()
    max_date = df["T"].max().date()
    date_range = st.sidebar.date_input(
        "Date Range",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date,
    )

    if isinstance(date_range, tuple) and len(date_range) == 2:
        start_date, end_date = date_range
        df = df[(df["T"].dt.date >= start_date) & (df["T"].dt.date <= end_date)]

# Client (IP/Hostname) filter
unique_clients = sorted(df["hostname"].unique())
selected_clients = st.sidebar.multiselect(
    "Select Clients (Hostnames/IPs)",
    options=unique_clients,
    default=[],
    help="Filter by client device. Leave empty to show all.",
)

if selected_clients:
    df = df[df["hostname"].isin(selected_clients)]

# Top-level domain filter
unique_domains = sorted(df["top_level_domain"].unique())
selected_domains = st.sidebar.multiselect(
    "Select Domains (Top-Level)",
    options=unique_domains,
    default=[],
    help="Filter by top-level domain. Leave empty to show all.",
)

if selected_domains:
    df = df[df["top_level_domain"].isin(selected_domains)]

# Query type filter
unique_query_types = sorted(df["QT"].unique())
selected_query_types = st.sidebar.multiselect(
    "Query Types",
    options=unique_query_types,
    default=[],
    help="Filter by DNS query type (A, AAAA, HTTPS, etc.)",
)

if selected_query_types:
    df = df[df["QT"].isin(selected_query_types)]

# Filter status
filter_options = ["All", "Filtered Only", "Not Filtered Only"]
filter_selection = st.sidebar.radio("Filter Status", filter_options)

if filter_selection == "Filtered Only":
    df = df[df["is_filtered"]]
elif filter_selection == "Not Filtered Only":
    df = df[~df["is_filtered"]]

# Overview metrics
st.header("📊 Overview")

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric("Total Queries", f"{len(df):,}")

with col2:
    blocked = df["is_filtered"].sum()
    blocked_pct = (blocked / len(df) * 100) if len(df) > 0 else 0
    st.metric("Blocked Queries", f"{blocked:,} ({blocked_pct:.1f}%)")

with col3:
    unique_domains_count = df["top_level_domain"].nunique()
    st.metric("Unique Domains", f"{unique_domains_count:,}")

with col4:
    unique_clients_count = df["hostname"].nunique()
    st.metric("Active Clients", f"{unique_clients_count:,}")

with col5:
    if "Cached" in df.columns:
        cached = df["Cached"].fillna(False).sum()
        cached_pct = (cached / len(df) * 100) if len(df) > 0 else 0
        st.metric("Cached", f"{cached:,} ({cached_pct:.1f}%)")
    else:
        st.metric("Cached", "N/A")

# Charts
st.header("📈 Analytics")

tab1, tab2, tab3, tab4 = st.tabs(
    ["📅 Timeline", "🌐 Domains", "💻 Clients", "🔒 Filtering"]
)

with tab1:
    st.subheader("Queries Over Time")

    # Resample by hour, grouped by client
    if len(df) > 0:
        # Group by hour and client
        timeline_df = (
            df.groupby([pd.Grouper(key="T", freq="h"), "hostname"])
            .size()
            .reset_index(name="Queries")
        )
        timeline_df.columns = ["Time", "Client", "Queries"]

        fig = px.line(
            timeline_df,
            x="Time",
            y="Queries",
            color="Client",
            title="DNS Queries per Hour by Client",
        )
        fig.update_layout(
            xaxis_title="Time",
            yaxis_title="Number of Queries",
            hovermode="x unified",
            legend_title_text="Client",
        )
        st.plotly_chart(fig, width="stretch")

        # Queries by hour of day
        st.subheader("Queries by Hour of Day")
        df["hour"] = df["T"].dt.hour
        hourly_counts = df.groupby("hour").size().reset_index()
        hourly_counts.columns = ["Hour", "Queries"]

        fig2 = px.bar(
            hourly_counts,
            x="Hour",
            y="Queries",
            title="Query Distribution by Hour of Day",
        )
        fig2.update_layout(
            xaxis_title="Hour of Day",
            yaxis_title="Number of Queries",
            xaxis={"dtick": 1},
        )
        st.plotly_chart(fig2, width="stretch")

with tab2:
    st.subheader("Top Queried Domains")

    # Top domains
    top_domains = df["top_level_domain"].value_counts().head(20).reset_index()
    top_domains.columns = ["Domain", "Queries"]

    fig3 = px.bar(
        top_domains,
        x="Queries",
        y="Domain",
        orientation="h",
        title="Top 20 Queried Domains (by Top-Level Domain)",
    )
    fig3.update_layout(yaxis={"categoryorder": "total ascending"})
    st.plotly_chart(fig3, width="stretch")

    # Domain pie chart
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Domain Distribution (Top 10)")
        top_10_domains = df["top_level_domain"].value_counts().head(10).reset_index()
        top_10_domains.columns = ["Domain", "Queries"]

        fig4 = px.pie(
            top_10_domains,
            values="Queries",
            names="Domain",
            title="Top 10 Domains",
        )
        st.plotly_chart(fig4, width="stretch")

    with col2:
        st.subheader("Query Types Distribution")
        query_types = df["QT"].value_counts().reset_index()
        query_types.columns = ["Type", "Count"]

        fig5 = px.pie(
            query_types,
            values="Count",
            names="Type",
            title="DNS Query Types",
        )
        st.plotly_chart(fig5, width="stretch")

with tab3:
    st.subheader("Client Activity")

    # Queries per client
    client_queries = df["hostname"].value_counts().reset_index()
    client_queries.columns = ["Client", "Queries"]

    fig6 = px.bar(
        client_queries.head(20),
        x="Queries",
        y="Client",
        orientation="h",
        title="Top 20 Most Active Clients",
    )
    fig6.update_layout(yaxis={"categoryorder": "total ascending"})
    st.plotly_chart(fig6, width="stretch")

    # Client breakdown
    st.subheader("Client Details")
    client_stats = (
        df.groupby("hostname")
        .agg(
            Total_Queries=("hostname", "count"),
            Unique_Domains=("top_level_domain", "nunique"),
            Blocked=("is_filtered", "sum"),
        )
        .reset_index()
    )
    client_stats["Block_Rate"] = (
        client_stats["Blocked"] / client_stats["Total_Queries"] * 100
    ).round(1)
    client_stats = client_stats.sort_values("Total_Queries", ascending=False)
    client_stats.columns = [
        "Client",
        "Total Queries",
        "Unique Domains",
        "Blocked",
        "Block Rate (%)",
    ]

    st.dataframe(client_stats, width="stretch", hide_index=True)

with tab4:
    st.subheader("Filtering Statistics")

    col1, col2 = st.columns(2)

    with col1:
        # Filter reasons
        filter_counts = df["filter_status"].value_counts().reset_index()
        filter_counts.columns = ["Status", "Count"]

        fig7 = px.pie(
            filter_counts,
            values="Count",
            names="Status",
            title="Query Filter Status",
            color="Status",
            color_discrete_map={
                "Not Filtered": "#2ecc71",
                "Blocked by Rule": "#e74c3c",
                "Rewritten (Safe Search)": "#f39c12",
                "Blocked by Filter": "#e74c3c",
                "Blocked (Safebrowsing)": "#9b59b6",
            },
        )
        st.plotly_chart(fig7, width="stretch")

    with col2:
        # Top blocked domains
        blocked_df = df[df["is_filtered"]]
        if len(blocked_df) > 0:
            blocked_domains = (
                blocked_df["top_level_domain"].value_counts().head(10).reset_index()
            )
            blocked_domains.columns = ["Domain", "Blocked Count"]

            fig8 = px.bar(
                blocked_domains,
                x="Blocked Count",
                y="Domain",
                orientation="h",
                title="Top 10 Blocked Domains",
                color_discrete_sequence=["#e74c3c"],
            )
            fig8.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(fig8, width="stretch")
        else:
            st.info("No blocked queries in the selected data.")

    # Blocked queries over time
    if len(blocked_df) > 0:
        st.subheader("Blocked Queries Over Time")
        blocked_timeline = blocked_df.set_index("T").resample("h").size().reset_index()
        blocked_timeline.columns = ["Time", "Blocked"]

        fig9 = px.area(
            blocked_timeline,
            x="Time",
            y="Blocked",
            title="Blocked Queries per Hour",
            color_discrete_sequence=["#e74c3c"],
        )
        st.plotly_chart(fig9, width="stretch")

# Raw data
st.header("📋 Query Log")

# Show/hide raw data
if st.checkbox("Show raw query data"):
    display_df = df[
        [
            "T",
            "hostname",
            "QH",
            "top_level_domain",
            "QT",
            "filter_status",
            "Upstream",
        ]
    ].copy()
    display_df.columns = [
        "Time",
        "Client",
        "Queried Host",
        "Top-Level Domain",
        "Query Type",
        "Status",
        "Upstream DNS",
    ]
    display_df = display_df.sort_values("Time", ascending=False)

    # Search in raw data
    search = st.text_input("Search in queries", "")
    if search:
        mask = display_df.apply(lambda row: search.lower() in str(row).lower(), axis=1)
        display_df = display_df[mask]

    st.dataframe(
        display_df.head(500),
        width="stretch",
        hide_index=True,
    )
    if len(display_df) > 500:
        st.caption(f"Showing first 500 of {len(display_df)} entries")
