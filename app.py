import os
import streamlit as st
import pandas as pd
import json
import sqlite3
import plotly.express as px

# Path to the symbolic link we created
IOT_DB_PATH = 'dionaea_iot.sqlite'
COWRIE_LOG_PATH = 'var/log/cowrie/cowrie.json'

st.set_page_config(page_title="IoT Honeypot Analyzer", layout="wide")
st.title("IoT Deception Network: Threat Analysis")

# --- DATA LOADING FUNCTIONS ---

def load_cowrie_data():
    data = []
    if not os.path.exists(COWRIE_LOG_PATH):
        return pd.DataFrame()
    with open(COWRIE_LOG_PATH, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)
                # We only want login attempts and command executions for the charts
                if entry['eventid'] in ['cowrie.login.success', 'cowrie.login.failed', 'cowrie.command.input']:
                    data.append({
                        'timestamp': entry['timestamp'],
                        'eventid': entry['eventid'].replace('cowrie.', ''), # Clean up names
                        'src_ip': entry.get('src_ip', '0.0.0.0'),
                        'username': entry.get('username', 'N/A'),
                        'password': entry.get('password', 'N/A'),
                        'input': entry.get('input', '') # For commands
                    })
            except:
                continue


    df = pd.DataFrame(data)
    if not df.empty:
        # Convert to proper time format
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

def load_iot_data():
    if not os.path.exists(IOT_DB_PATH):
        return pd.DataFrame()
    try:
        conn = sqlite3.connect(IOT_DB_PATH)
        query = "SELECT connection_timestamp, remote_host, local_port FROM connections ORDER BY connection_timestamp DESC"
        df_iot = pd.read_sql_query(query, conn)
        conn.close()

        if not df_iot.empty:
            df_iot.columns = ['Timestamp', 'Attacker IP', 'Port']
            df_iot['Timestamp'] = pd.to_datetime(df_iot['Timestamp'], unit='s', errors='coerce')
            df_iot['Timestamp'] = df_iot['Timestamp'] + pd.Timedelta(hours=1)
            df_iot = df_iot.dropna(subset=['Timestamp'])

            # Port mapping for IoT and Infrastructure
            port_map = {1883: "MQTT", 445: "SMB", 3306: "MySQL", 1433: "MSSQL", 81: "HTTP-Alt", 135: "RPC"}
            df_iot['Protocol'] = df_iot['Port'].map(lambda x: port_map.get(x, f"Port {x}"))
            return df_iot


    except Exception as e:
        st.error(f"Error reading Dionaea logs: {e}")
        return pd.DataFrame()

# --- DASHBOARD LAYOUT ---

tab1, tab2 = st.tabs(["SSH Analytics (Cowrie)", "IoT & Protocol Sensors (Dionaea)"])

with tab1:
    st.header("SSH Attack Activity")
    cowrie_df = load_cowrie_data()

    if not cowrie_df.empty:
        # Usernames and Passwords Columns
        col_u, col_p = st.columns(2)

        with col_u:
            st.subheader("Top Usernames Attempted")
            user_counts = cowrie_df['username'].value_counts().head(10).reset_index()
            fig_user = px.bar(user_counts, x='username', y='count', color='count', template="plotly_dark")
            st.plotly_chart(fig_user, width='stretch')

        with col_p:
            st.subheader("Top Passwords Attempted")
            pass_counts = cowrie_df['password'].value_counts().head(10).reset_index()
            fig_pass = px.bar(pass_counts, x='password', y='count', color='count', 
                             color_continuous_scale='Reds', template="plotly_dark")
            st.plotly_chart(fig_pass, use_container_width=True)

        st.subheader("Recent SSH Logins")
        # Updated width parameter for 2026 standards
        sorted_cowrie = cowrie_df.sort_values(by='timestamp', ascending=False)
        st.dataframe(sorted_cowrie, height=400, use_container_width=True)
    else:
        st.info("No SSH logs yet.")

with tab2:
    st.header("IoT & Service Probes")
    iot_df = load_iot_data()

    if not iot_df.empty:
        # IoT Timeline Chart
        st.subheader("IoT Probe Frequency")
        try:
            fig_iot = px.histogram(iot_df, x='Timestamp', color='Protocol', 
                                   title="Probes Detected Over Time", template="plotly_dark",
                                   nbins=30) # nbins adjusts how clustered the bars are
            fig_iot.update_layout(bargap=0.1)
            st.plotly_chart(fig_iot, use_container_width=True)
        except Exception as e:
            st.warning(f"Could not generate timeline: {e}")
        st.subheader("All IoT Activity Data (Scrollable)")
        # FIX: Using st.dataframe instead of st.table so you can scroll through hundreds of records
        sorted_iot = iot_df.sort_values(by='Timestamp', ascending=False)
        st.dataframe(sorted_iot, height=400, use_container_width=True)
    else:
        st.info("No IoT probes detected yet.")

with st.tabs(["SSH Analytics", "IoT Sensors", "Threat Intel & Response"])[2]:
    st.header("Automated Network Defense")
    st.write("Convert captured attacker IPs into actionable router firewall rules.")
    
    # We use the cowrie data we already loaded
    if not cowrie_df.empty:
        # Get the top 5 most aggressive unique IPs
        top_ips = cowrie_df['src_ip'].value_counts().head(5).index.tolist()
        
        st.subheader("Generate Cisco IOS Blocklist")
        st.write("Apply these ACL commands to the perimeter edge router to block known threats:")
        
        # Generate the Cisco commands
        cisco_commands = "enable\nconfigure terminal\nip access-list extended HONEYPOT_BLOCK\n"
        for ip in top_ips:
            cisco_commands += f"deny ip host {ip} any log\n"
        cisco_commands += "permit ip any any\nexit\n"
        cisco_commands += "interface GigabitEthernet0/0\n ip access-group HONEYPOT_BLOCK in\nend\nwrite memory"
        
        # Display as a copyable code block
        st.code(cisco_commands, language="bash")
    else:
        st.info("Gathering threat data... waiting for attacks.")
