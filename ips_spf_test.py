import streamlit as st
import spf
import concurrent.futures
import pandas as pd

st.set_page_config(page_title="SPF IP Checker", layout="wide")

st.title("🔍 SPF IP Checker")

# User input
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

# SPF check function
def check_spf(ip_address):
    try:
        result = spf.check2(ip_address, 'postmaster@' + domain, domain)
        return ip_address, result[0] if len(result) == 3 else "unexpected"
    except spf.TempError:
        return ip_address, "tempfail"
    except spf.PermError:
        return ip_address, "permfail"
    except Exception as e:
        return ip_address, f"error: {str(e)}"

# Run button
if st.button("🚀 Run SPF Check") and ips:
    st.info(f"Checking {len(ips)} IPs...")

    results = []
    progress_bar = st.progress(0)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        for i, result in enumerate(executor.map(check_spf, ips)):
            results.append(result)
            progress_bar.progress((i + 1) / len(ips))

    df = pd.DataFrame(results, columns=["IP", "Result"])

    # Summary
    st.subheader("📊 Summary")
    st.write({
        "Pass": (df["Result"] == "pass").sum(),
        "Fail": df["Result"].isin(["fail", "softfail"]).sum(),
        "Neutral": (df["Result"] == "neutral").sum(),
        "Errors": df["Result"].str.contains("error|tempfail|permfail").sum()
    })

    # Table
    st.subheader("📋 Results")
    st.dataframe(df, use_container_width=True)

    # Download
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇️ Download Results",
        csv,
        "spf_results.csv",
        "text/csv"
    )

elif st.button("🚀 Run SPF Check"):
    st.warning("Please provide IPs first.")