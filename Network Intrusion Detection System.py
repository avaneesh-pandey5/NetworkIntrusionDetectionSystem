#--------IMPORTING ALL THE NECESSARY MODULES----------

import pickle
import pandas as pd
import plotly.express as px
import streamlit as st
from sklearn.preprocessing import StandardScaler
import streamlit.config as config
import time

#-----------LOADING OUR BEST MODEL, RANDOM FOREST CLASSIFIER AND THE OBJECT OF STANDARD SCALER TO SCALE THE DATA-------

with open('rfc_new.pickle', 'rb') as file:
    rfc = pickle.load(file)

with open('scaler.pickle','rb') as file:
    scaler = pickle.load(file)


#--------USING STREAMLIT TO CREATE OUR WEB APPLICATION-----------
#-------CONFIGURING THE DASHBOARD-------

st.set_page_config(page_title="Network Intrusion Detection",
                   page_icon=":bar_chart:",
                   layout='wide')

st.title(":bar_chart: Network Intrusion Detection")
st.write("Upload a CSV file and get predictions using the trained model.")


#--------CREATING THE UPLOAD FILE OPTION ---------------

uploaded_file = st.file_uploader("Upload a CSV file", type="csv")


#----------MAIN FUNCTION-------------

if uploaded_file is not None:

    #------READING THE FILE AS A PANDAS DATAFRAME----------

    df = pd.read_csv(uploaded_file)

    #------SCALING THE DATA USING THE PRE LOADED SCALER------

    scaled_df = scaler.transform(df)

    #---- PREDICTING THE VALUES USING RANDOM FOREST CLASSIFIER MODEL THAT WE TRAINED ON TRAINING DATA-------

    predicted_values = rfc.predict(scaled_df)
    df['CLASS'] = predicted_values

    #----MAPPING THE NUMBERS BACK TO THEIR ACTUAL VALUES FOR A BETTER VISUAL REPRESENTATION-----

    df['protocol_type'] = df['protocol_type'].map({0:'TCP', 1:'UDP', 2:'ICMP'})
    df['service'] = df['service'].map({0.0: 'ftp_data', 1.0: 'other', 2.0: 'private', 3.0: 'http', 4.0: 'remote_job', 5.0: 'name', 6.0: 'netbios_ns', 7.0: 'eco_i', 8.0: 'mtp', 9.0: 'telnet', 10.0: 'finger', 11.0: 'domain_u', 12.0: 'supdup', 13.0: 'uucp_path', 14.0: 'Z39_50', 15.0: 'smtp', 16.0: 'csnet_ns', 17.0: 'uucp', 18.0: 'netbios_dgm', 19.0: 'urp_i', 20.0: 'auth', 21.0: 'domain', 22.0: 'ftp', 23.0: 'bgp', 24.0: 'ldap', 25.0: 'ecr_i', 26.0: 'gopher', 27.0: 'vmnet', 28.0: 'systat', 29.0: 'http_443', 30.0: 'efs', 31.0: 'whois', 32.0: 'imap4', 33.0: 'iso_tsap', 34.0: 'echo', 35.0: 'klogin', 36.0: 'link', 37.0: 'sunrpc', 38.0: 'login', 39.0: 'kshell', 40.0: 'sql_net', 41.0: 'time', 42.0: 'hostnames', 43.0: 'exec', 44.0: 'ntp_u', 45.0: 'discard', 46.0: 'nntp', 47.0: 'courier', 48.0: 'ctf', 49.0: 'ssh', 50.0: 'daytime', 51.0: 'shell', 52.0: 'netstat', 53.0: 'pop_3', 54.0: 'nnsp', 55.0: 'IRC', 56.0: 'pop_2', 57.0: 'printer', 58.0: 'tim_i', 59.0: 'pm_dump', 60.0: 'red_i', 61.0: 'netbios_ssn', 62.0: 'rje', 63.0: 'X11', 64.0: 'urh_i', 65.0: 'http_8001'})
    df['flag'] = df['flag'].map({0: 'SF', 1: 'S0', 2: 'REJ', 3: 'RSTR', 4: 'SH', 5: 'RSTO', 6: 'S1', 7: 'RSTOS0', 8: 'S3', 9: 'S2', 10: 'OTH'})
    df['CLASS'] = df['CLASS'].map({1:'ABNORMAL',0:'NORMAL'})

    # -- SETTING THE WIDTH OF THE SIDE BAR----

    config.set_option('deprecation.showfileUploaderEncoding', False)
    st.markdown(
        f"""
        <style>
        .reportview-container .main .block-container{{
            max-width: 1200px;
            padding-top: 1rem;
            padding-right: 1rem;
            padding-left: 1rem;
            padding-bottom: 1rem;
        }}
        .sidebar .sidebar-content {{
            width: 250px;
        }}
        </style>
        """,
        unsafe_allow_html=True
    )

    #-----CREATING THE SIDEBAR----

    st.sidebar.header("Please Select a Category")

    clss = st.sidebar.selectbox("Select Class", ["ABNORMAL","NORMAL"],index=0)

    df_selection = df.query("CLASS == @clss")

    #----------------------------------#
    # ---------- MAIN PAGE -------------
    #----------------------------------#

    st.subheader(f"The total number of {clss} Networks are {sum(df['CLASS']==clss)}")
    st.markdown('##')
    st.markdown('##')

    #-----PRINTING THE DATAFRAME(TABLE) ON THE WEB APP-----

    st.dataframe(df_selection)

    #--------- PROTOCOL DISTRIBUTION GRAPH----------

    protocol_type_pie = px.pie(df_selection['protocol_type'].value_counts(), names=df_selection['protocol_type'].value_counts().index)
    protocol_type_pie.update_traces(hole=0.4)


    protocol_type_pie.update_layout(
        title={
            'text': "Protocol Type Distribution",
            'y': 0.95,
            'x': 0.4,
            'xanchor': 'center',
            'yanchor': 'top',
            'font': {'size': 24}
        },legend=dict(font=dict(size=20))
    )

    st.plotly_chart(protocol_type_pie)

    #-------- SERVICE TYPE DISTRIBUTION BAR GRAPH----------

    service_type_bar = px.bar(df_selection['service'].value_counts(),y='count')

    service_type_bar.update_layout(
        title={
            'text': "Service Type Distribution",
            'y': 0.95,
            'x': 0.4,
            'xanchor': 'center',
            'yanchor': 'top',
            'font': {'size': 24}
        })

    st.plotly_chart(service_type_bar)

    #-----FLAG TYPE DISTRIBUTION PIE CHART----------

    flag_type_pie = px.pie(df_selection['flag'].value_counts(), names=df_selection['flag'].value_counts().index)
    flag_type_pie.update_traces(hole=0.4)

    flag_type_pie.update_layout(
        title={
            'text': "Flag Type Distribution",
            'y': 0.95,
            'x': 0.4,
            'xanchor': 'center',
            'yanchor': 'top',
            'font': {'size': 24}
        },legend=dict(font=dict(size=15))
    )

    st.plotly_chart(flag_type_pie)


    #-----------------END--------------------

