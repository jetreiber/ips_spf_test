import streamlit as st
import dns.resolver
import concurrent.futures
import pandas as pd
import ipaddress

st.set_page_config(page_title="SPF IP Checker", layout="wide")

st.title("🔍 SPF IP Checker (Advanced)")

# ---------------------------
# INPUTS
# ---------------------------
domain = st.text_input("Enter domain", value="Enter domain")

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
# DNS HELPERS
# ---------------------------
def resolve_txt(domain):
    try:
        return dns.resolver.resolve(domain, 'TXT')
    except:
        return []

def resolve_a(domain):
    try:
        return [r.address for r in dns.resolver.resolve(domain, 'A')]
    except:
        return []

def resolve_mx(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        hosts = [r.exchange.to_text().rstrip('.') for r in mx_records]
        ips = []
        for host in hosts:
            ips.extend(resolve_a(host))
        return ips
    except:
        return []

def get_spf_record(domain):
    for rdata in resolve_txt(domain):
        txt = "".join([
            part.decode() if isinstance(part, bytes) else part
            for part in rdata.strings
        ])
        if txt.startswith("v=spf1"):
            return txt
    return None

# ---------------------------
# SPF ENGINE (ADVANCED)
# ---------------------------
def check_ip_in_spf(ip, domain, visited=None):
    if visited is None:
        visited = set()

    if domain in visited:
        return False
    visited.add(domain)

    spf_record = get_spf_record(domain)
    if not spf_record:
        return False

    ip_obj = ipaddress.ip_address(ip)
    parts = spf_record.split()

    for part in parts:
        part = part.strip()

        # ip4
        if part.startswith("ip4:"):
            cidr = part.replace("ip4:", "")
            try:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return True
            except:
                continue

        # include
        elif part.startswith("include:"):
            include_domain = part.replace("include:", "")
            if check_ip_in_spf(ip, include_domain, visited):
                return True

        # a mechanism
        elif part == "a" or part.startswith("a:"):
            target = domain if part == "a" else part.split(":", 1)[1]
            for resolved_ip in resolve_a(target):
                if ip == resolved_ip:
                    return True

        # mx mechanism
        elif part == "mx" or part.startswith("mx:"):
            target = domain if part == "mx" else part.split(":", 1)[1]
            for resolved_ip in resolve_mx(target):
                if ip == resolved_ip:
                    return True

    return False


def evaluate_spf(ip, domain):
    try:
        if check_ip_in_spf(ip, domain):
            return "pass"

        spf_record = get_spf_record(domain)

        if spf_record:
            if "-all" in spf_record:
                return "fail"
            elif "~all" in spf_record:
                return "softfail"

        return "neutral"

    except Exception as e:
        return f"error: {e}"

# ---------------------------
# RUN BUTTON
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
                return ip, evaluate_spf(ip, domain)

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
            # RESULTS
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
