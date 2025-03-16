import streamlit as st
import streamlit.components.v1 as components
import numpy as np
import pandas as pd
import socket
import psutil
import platform
import threading
import subprocess
import plotly.express as px
from tensorflow.keras.models import load_model

# -------------- Page Config --------------
st.set_page_config(page_title="Smart City AI Security", layout="wide")

# -------------- Custom Dark Theme --------------
st.markdown("""
    <style>
    body {
        background-color: #0e1117;
        color: white;
    }
    .block-container {
        padding: 2rem;
    }
    .stButton>button {
        background-color: #262730;
        color: white;
        border: 1px solid #565656;
    }
    .stTextInput>div>div>input {
        background-color: #1c1e26;
        color: white;
    }
    .stTextArea textarea {
        background-color: #1c1e26;
        color: white;
    }
    .stSelectbox>div>div>div {
        background-color: #1c1e26;
        color: white;
    }
    </style>
""", unsafe_allow_html=True)

# -------------- Spline Background --------------
components.html("""
    <div style="position:fixed;top:0;left:0;width:100vw;height:100vh;z-index:-1;">
        <spline-viewer url="https://prod.spline.design/LRjbN8y7HUnFeIsX/scene.splinecode"></spline-viewer>
    </div>
    <script type="module" src="https://unpkg.com/@splinetool/viewer@1.9.79/build/spline-viewer.js"></script>
""", height=0)

# -------------- Header --------------
st.markdown("<h1 style='text-align: center;'>🌐 Smart City Security Dashboard</h1>", unsafe_allow_html=True)
st.markdown("A real-time AI-driven system for protecting Smart City IoT and network infrastructure.")

# -------------- Tabs ------------------
tab = st.selectbox("Choose Section", ["🏠 Home", "🔐 Prediction", "🛠️ Device Scanner"])

# -------------- Home ------------------
if tab == "🏠 Home":
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("🔐 Features")
        st.markdown("""
        - AI-powered intrusion prediction  
        - Network port vulnerability scanner  
        - CVE analysis for open ports  
        - CSV / manual input support  
        - PDF and cloud-ready architecture  
        """)

    with col2:
        st.subheader("🚀 Coming Soon")
        st.markdown("""
        - Role-based Login  
        - Realtime Firebase/GDrive Sync  
        - Email Alerts & PDF Reports  
        - IoT Device Control Dashboard  
        """)

    st.markdown("---")
    st.success("⚙️ System Ready. Choose a feature from above.")

# -------------- Prediction ------------------
elif tab == "🔐 Prediction":
    st.subheader("🧠 AI-Based Intrusion Detection")

    try:
        model = load_model("Model.h5")
        class_labels = ['Normal', 'Dos', 'Probe', 'R2L', 'U2R']

        input_mode = st.radio("Input Mode", ["Manual Entry", "Upload CSV"])

        def predict(data):
            data = data.reshape(data.shape[0], data.shape[1], 1)
            preds = model.predict(data)
            return [class_labels[i] for i in np.argmax(preds, axis=1)]

        if input_mode == "Manual Entry":
            default_values = [0.0] * 32
            user_input = st.text_area("🔢 Enter 32 comma-separated values:", value=", ".join(map(str, default_values)))

            if st.button("🔮 Predict"):
                try:
                    values = list(map(float, user_input.strip().split(',')))
                    if len(values) != 32:
                        st.error("❌ You must enter exactly 32 values.")
                    else:
                        result = predict(np.array(values).reshape(1, 32))
                        st.success(f"✅ Prediction: **{result[0]}**")
                        df = pd.DataFrame({"Prediction": [result[0]]})
                        st.plotly_chart(px.pie(df, names="Prediction", title="Prediction Result"))
                except Exception as e:
                    st.error(f"⚠️ Error: {e}")

        elif input_mode == "Upload CSV":
            file = st.file_uploader("📁 Upload CSV file with 32 features", type=["csv"])
            if file:
                df = pd.read_csv(file)
                if df.shape[1] != 32:
                    st.error("❌ CSV must have exactly 32 columns.")
                else:
                    if st.button("🔮 Predict All"):
                        predictions = predict(df.values)
                        df['Prediction'] = predictions
                        st.dataframe(df)
                        st.plotly_chart(px.histogram(df, x="Prediction", color="Prediction", title="Prediction Results"))

    except Exception as e:
        st.error(f"⚠️ Failed to load model: {e}")

# -------------- Device Scanner ------------------
elif tab == "🛠️ Device Scanner":
    st.subheader("💻 Device Vulnerability Scan")

    def get_device_info():
        return {
            "Hostname": socket.gethostname(),
            "IP Address": socket.gethostbyname(socket.gethostname()),
            "OS": platform.system(),
            "OS Version": platform.version(),
            "CPU": platform.processor(),
            "RAM": f"{round(psutil.virtual_memory().total / (1024**3), 2)} GB"
        }

    def check_ports():
        ports = []
        common = [21, 22, 23, 80, 135, 139, 443, 445, 3306, 3389]
        ip = socket.gethostbyname(socket.gethostname())

        def scan(p, out):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.05)
                    if sock.connect_ex((ip, p)) == 0:
                        out.append(p)
            except:
                pass

        results = []
        threads = [threading.Thread(target=scan, args=(p, results)) for p in common]
        for t in threads: t.start()
        for t in threads: t.join()
        return results

    def scan_network():
        found = set()
        try:
            arp = subprocess.check_output("arp -a", shell=True).decode()
            for line in arp.splitlines():
                if '-' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        if not ip.startswith(("224.", "239.", "255.")):
                            found.add(ip)
        except:
            pass
        return list(found)

    # Device Info
    st.write("### 🧾 Device Information")
    st.table(pd.DataFrame.from_dict(get_device_info(), orient="index", columns=["Value"]))

    if st.button("🔍 Scan Open Ports"):
        open_ports = check_ports()
        if open_ports:
            st.warning(f"⚠️ Detected Open Ports: {open_ports}")
        else:
            st.success("✅ No open ports detected.")

    if st.button("📡 Scan Nearby Devices"):
        devices = scan_network()
        if devices:
            st.info("📶 Devices Found:")
            for d in devices:
                st.write(f"🔹 {d}")
        else:
            st.success("✅ No nearby devices found.")

# -------------- Footer --------------
st.markdown("---")
st.markdown("<center>🛡️ Designed with AI for Smart Cities | © 2025</center>", unsafe_allow_html=True)
