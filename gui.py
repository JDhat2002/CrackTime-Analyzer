import streamlit as st
from datetime import datetime, timezone

from cracktime_analyzer.core import analyze_password, estimate_crack_time_from_guesses, CRACK_SPEED_PRESETS
from cracktime_analyzer.report import save_json_report, save_csv_report


st.set_page_config(page_title="CrackTime Analyzer", page_icon="🔐", layout="centered")

st.title("🔐 CrackTime Analyzer")
st.write("Estimate password strength and crack times. **Do not use real passwords** – demo only.")


# Sidebar options
st.sidebar.header("⚙️ Options")
preset = st.sidebar.selectbox(
    "Attacker speed preset",
    options=list(CRACK_SPEED_PRESETS.keys()),
    index=1,
    format_func=lambda x: f"{x} ({CRACK_SPEED_PRESETS[x]:.0e} guesses/sec)"
)
custom_speed = st.sidebar.number_input(
    "Custom guesses/sec (overrides preset)",
    min_value=0.0,
    value=0.0,
    step=1000.0
)
output_prefix = st.sidebar.text_input("Output prefix for reports (optional)", "gui_report")


# Main input
password = st.text_input("Enter a password to analyze", type="password")

if st.button("Analyze"):
    if not password:
        st.warning("⚠️ Please enter a password.")
    else:
        # Analyze
        result = analyze_password(password)
        guesses = result["guesses"]
        speed = custom_speed if custom_speed > 0 else CRACK_SPEED_PRESETS[preset]
        timeinfo = estimate_crack_time_from_guesses(guesses, speed)
        result["crack_time_seconds"] = timeinfo["seconds"]
        result["crack_time_human"] = timeinfo["human_readable"]
        result["assumptions"] = {"preset": preset, "guesses_per_second": speed}

        # Strength meter
        score = result["score"] or 0
        labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
        colors = ["🔴", "🟠", "🟡", "🟢", "🔵"]

        st.subheader("📊 Password Strength")
        st.write(f"{colors[score]} **{labels[score]}** (score {score}/4)")
        st.progress((score + 1) * 20)

        # Crack time gauge
        st.subheader("⏱️ Estimated Crack Time")
        crack_seconds = result["crack_time_seconds"]
        st.write(f"Estimated time to crack: **{result['crack_time_human']}**")

        # Normalize crack time for gauge (log scale)
        import math
        # Define thresholds for scaling (1s → 1 year)
        thresholds = [1, 60, 3600, 86400, 31557600]  # sec, min, hr, day, year
        max_threshold = thresholds[-1]

        progress_val = min(1.0, math.log10(crack_seconds + 1) / math.log10(max_threshold + 1))
        st.progress(progress_val)

        if crack_seconds < 60:
            st.info("⚠️ Easily crackable in under a minute.")
        elif crack_seconds < 3600:
            st.warning("⌛ Crackable within an hour.")
        elif crack_seconds < 86400:
            st.warning("⏳ Crackable within a day.")
        elif crack_seconds < 31557600:
            st.success("🟢 Resistant for months to a year.")
        else:
            st.success("🔒 Very strong: estimated > 1 year to crack.")

        # Show detailed JSON
        st.subheader("📋 Detailed Analysis")
        st.json(result)

        # Save reports
        meta = {
            "tool": "CrackTime Analyzer",
            "version": "0.1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        json_file = f"{output_prefix}_{timestamp}.json"
        csv_file = f"{output_prefix}_{timestamp}.csv"

        save_json_report(meta, [result], json_file)
        save_csv_report(meta, [result], csv_file)

        with open(json_file, "rb") as f:
            st.download_button("⬇️ Download JSON report", f, file_name=json_file, mime="application/json")

        with open(csv_file, "rb") as f:
            st.download_button("⬇️ Download CSV report", f, file_name=csv_file, mime="text/csv")

        st.success("✅ Analysis complete and reports generated.")
