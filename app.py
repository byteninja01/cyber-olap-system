import streamlit as st

st.set_page_config(
    page_title="CyberSec OLAP System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Sidebar nav ───────────────────────────────────────────
st.sidebar.title("🛡️ CyberSec OLAP")
st.sidebar.caption("CIC-IDS-2017 · PortScan Dataset")
st.sidebar.divider()

page = st.sidebar.radio("Navigate", [
    "🏠 Overview",
    "🧊 OLAP Explorer",
    "🤖 ML Models",
    "📡 Live Stream",
    "🔎 Flow Inspector",
])

st.sidebar.divider()
st.sidebar.caption("Friday WorkingHours Afternoon PortScan")

# ── Page routing ──────────────────────────────────────────
if   page == "Overview":       from pages import overview;    overview.render()
elif page == "OLAP Explorer":  from pages import olap_page;   olap_page.render()
elif page == "ML Models":      from pages import ml_page;     ml_page.render()
elif page == "Live Stream":    from pages import stream_page; stream_page.render()
elif page == "Flow Inspector": from pages import inspector;   inspector.render()