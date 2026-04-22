import streamlit as st
import dns.resolver
import concurrent.futures
import pandas as pd
import ipaddress

st.set_page_config(page_title="SPF IP Checker", layout="wide")

st.title("🔍 SPF IP Checker (Modern)")

# ---------------------------
# INPUTS
# ---------------------------
domain = st.text_input("Enter domain", value="amasonses.com")

input_method = st.radio("Choose input method:", ["Paste IPs", "Upload file"])

ips = []

if input_method == "Paste IPs":
    ip_text = st.text_area("Enter IPs (one per line)")
    if ip_text:
        ips = [line.strip() for line in ip_text.splitlines() if line.strip()]

elif input_method == "Upload file":
    uploaded_file = st.file_uploader("Upload a .txt file with IPs")
    if uploaded_file:
        ips = uploaded_file.read().decode("utf-8").splitlines()
        ips = [ip.strip() for ip in ips if ip.strip()]

# ---------------------------
# SPF LOGIC
# ---------------------------
def get_spf_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = "".join([
                part.decode() if isinstance(part, bytes) else part
                for part in rdata.strings
            ])
            if txt.startswith("v=spf1"):
                return txt
    except Exception:
        return None
    return None


def ip_in_spf(ip, spf_record):
    try:
        ip_obj = ipaddress.ip_address(ip)
        parts = spf_record.split()

        for part in parts:
            if part.startswith("ip4:"):
                cidr = part.replace("ip4:", "")
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return "pass"

        if "-all" in spf_record:
            return "fail"
        elif "~all" in spf_record:
            return "softfail"
        else:
            return "neutral"

    except Exception as e:
        return f"error: {e}"

# ---------------------------
# RUN BUTTON (FIXED)
# ---------------------------
run_button = st.button("🚀 Run SPF Check")

if run_button:
    if not ips:
        st.warning("⚠️ Please provide IPs first")
    else:
        st.info(f"Checking {len(ips)} IPs...")

        spf_record = get_spf_record(domain)

        if not spf_record:
            st.error("❌ No SPF record found")
        else:
            st.subheader("📄 SPF Record")
            st.code(spf_record, language="text")

            results = []
            progress = st.progress(0)

            def worker(ip):
                return ip, ip_in_spf(ip, spf_record)

            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                for i, result in enumerate(executor.map(worker, ips)):
                    results.append(result)
                    progress.progress((i + 1) / len(ips))

            df = pd.DataFrame(results, columns=["IP", "Result"])

            # ---------------------------
            # SUMMARY
            # ---------------------------
            st.subheader("📊 Summary")
            st.write({
                "Pass": (df["Result"] == "pass").sum(),
                "Fail": df["Result"].isin(["fail", "softfail"]).sum(),
                "Neutral": (df["Result"] == "neutral").sum(),
                "Errors": df["Result"].str.contains("error").sum()
            })

            # ---------------------------
            # RESULTS TABLE
            # ---------------------------
            st.subheader("📋 Results")
            st.dataframe(df, use_container_width=True)

            # ---------------------------
            # DOWNLOAD
            # ---------------------------
            st.download_button(
                "⬇️ Download Results",
                df.to_csv(index=False).encode(),
                "spf_results.csv",
                "text/csv"
            )
