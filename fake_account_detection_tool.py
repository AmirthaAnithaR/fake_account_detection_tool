import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from fuzzywuzzy import fuzz
from datetime import datetime
from collections import Counter
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from io import BytesIO
import requests
from PIL import Image as PILImage

# --- 1. SECURE ACCESS CONFIGURATION ---
st.set_page_config(
    page_title="Thread Hunters | Secure Forensic Portal",
    page_icon="🛡️",
    layout="wide"
)

# Mock Database for Officers (In production, use secrets or a database)
OFFICER_CREDENTIALS = {
    "OFFICER_001": "Shield2026",
    "ADMIN_UNIT": "Forensics99"
}

# Report threshold configuration
REPORT_THRESHOLD = 3  # Number of reports needed to remove an account

def login_page():
    """Renders the officer login interface"""
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<br><br>", unsafe_allow_html=True)
        st.image("https://cdn-icons-png.flaticon.com/512/1067/1067357.png", width=100)
        st.title("🛡️ Officer Authentication")
        st.info("Authorized Personnel Only - Access is Monitored")
        
        with st.form("login_form"):
            user_id = st.text_input("Officer ID")
            access_key = st.text_input("Access Key", type="password")
            submit = st.form_submit_button("Verify Credentials")
            
            if submit:
                if user_id in OFFICER_CREDENTIALS and OFFICER_CREDENTIALS[user_id] == access_key:
                    st.session_state["authenticated"] = True
                    st.session_state["officer_id"] = user_id
                    st.success("Access Granted. Initializing Forensic Engine...")
                    st.rerun()
                else:
                    st.error("Invalid Credentials. Access Denied.")

# Initialize Session State
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "reported_accounts" not in st.session_state:
    st.session_state["reported_accounts"] = {}  # {screen_name: report_count}
if "removed_accounts" not in st.session_state:
    st.session_state["removed_accounts"] = set()  # Set of removed screen_names

# --- GATEKEEPER ---
if not st.session_state["authenticated"]:
    login_page()
    st.stop()  # Stop execution here if not logged in

# --- 2. DATA & FORENSIC ENGINE (Only runs if authenticated) ---
@st.cache_data
def get_processed_data():
    # Load the dataset
    try:
        df = pd.read_csv('fusers_with_images.csv')
    except:
        # Fallback for demonstration if file is missing
        st.error("Data source 'fusers_with_images.csv' not found.")
        st.stop()
    
    def calculate_forensic_score(row):
        score = 0
        flags = []
        if row['default_profile'] == 1.0:
            score += 15
            flags.append("Default Profile Theme")
        if pd.notna(row.get('age_days')) and row['age_days'] < 180:
            score += 25
            flags.append(f"New Account ({row['age_days']} days old)")
        if row['friends_count'] > (row['followers_count'] * 15):
            score += 35
            flags.append("Suspicious Following Ratio")
        if row['statuses_count'] < 5:
            score += 20
            flags.append("Low Activity/New Account")
        if row.get('dataset') == 'FAKE':
            score += 50
            flags.append("⚠️ CONFIRMED FAKE ACCOUNT")
        if pd.notna(row['name']) and any(x in str(row['name']) for x in ['✓', '_Official', 'Real']):
            score += 30
            flags.append("Suspicious Name Pattern")
            
        category = "High Risk" if score >= 60 else ("Medium Risk" if score >= 30 else "Low Risk")
        return pd.Series([score, category, ", ".join(flags)])

    df[['risk_score', 'risk_category', 'risk_reasons']] = df.apply(calculate_forensic_score, axis=1)
    df['image_hash'] = df['image'].apply(lambda x: hash(x) if pd.notna(x) else None)
    return df

# --- 3. HELPER FUNCTIONS ---
def report_account(screen_name):
    """Report an account and track report count"""
    if screen_name not in st.session_state["reported_accounts"]:
        st.session_state["reported_accounts"][screen_name] = 0
    
    st.session_state["reported_accounts"][screen_name] += 1
    
    # Check if threshold reached
    if st.session_state["reported_accounts"][screen_name] >= REPORT_THRESHOLD:
        st.session_state["removed_accounts"].add(screen_name)
        return True  # Account removed
    return False  # Account reported but not removed

def filter_removed_accounts(df):
    """Filter out accounts that have been removed due to reports"""
    if st.session_state["removed_accounts"]:
        return df[~df['screen_name'].isin(st.session_state["removed_accounts"])]
    return df

def get_report_count(screen_name):
    """Get current report count for an account"""
    return st.session_state["reported_accounts"].get(screen_name, 0)

def analyze_impersonation_match(target, suspect):
    """Analyze and provide detailed reasons for impersonation match"""
    reasons = []
    risk_factors = []
    
    # Name similarity analysis
    name_similarity = fuzz.ratio(str(target['name']).lower(), str(suspect['name']).lower())
    if name_similarity >= 80:
        reasons.append(f"🔴 **High Name Similarity**: {name_similarity}% match between names")
        risk_factors.append("Critical")
    elif name_similarity >= 60:
        reasons.append(f"🟡 **Moderate Name Similarity**: {name_similarity}% match between names")
        risk_factors.append("Medium")
    else:
        reasons.append(f"🟢 **Low Name Similarity**: {name_similarity}% match between names")
    
    # Image hash comparison
    if target['image_hash'] == suspect['image_hash'] and target['image_hash'] is not None:
        reasons.append("🔴 **Identical Profile Images**: Both accounts use the exact same profile picture")
        risk_factors.append("Critical")
    
    # Account age comparison
    if pd.notna(target.get('age_days')) and pd.notna(suspect.get('age_days')):
        age_diff = abs(target['age_days'] - suspect['age_days'])
        if suspect['age_days'] < 180 and target['age_days'] > 365:
            reasons.append(f"🟡 **Suspicious Account Age**: Suspect account is only {suspect['age_days']} days old while target is {target['age_days']} days old")
            risk_factors.append("Medium")
    
    # Follower/Following ratio analysis
    if suspect['friends_count'] > (suspect['followers_count'] * 10):
        reasons.append(f"🔴 **Abnormal Following Pattern**: Suspect follows {suspect['friends_count']} but only has {suspect['followers_count']} followers")
        risk_factors.append("High")
    
    # Risk score comparison
    if suspect['risk_score'] >= 60:
        reasons.append(f"🔴 **High Risk Score**: Suspect has a risk score of {suspect['risk_score']}/100")
        risk_factors.append("Critical")
    elif suspect['risk_score'] >= 30:
        reasons.append(f"🟡 **Medium Risk Score**: Suspect has a risk score of {suspect['risk_score']}/100")
        risk_factors.append("Medium")
    
    # Default profile check
    if suspect['default_profile'] == 1.0:
        reasons.append("🟡 **Default Profile**: Suspect is using default profile theme")
        risk_factors.append("Low")
    
    # Activity level
    if suspect['statuses_count'] < 5:
        reasons.append(f"🟡 **Low Activity**: Suspect has only {suspect['statuses_count']} posts")
        risk_factors.append("Medium")
    
    # Overall verdict
    if "Critical" in risk_factors:
        verdict = "🚨 **HIGH PROBABILITY OF IMPERSONATION**"
        verdict_color = "error"
    elif "High" in risk_factors or risk_factors.count("Medium") >= 2:
        verdict = "⚠️ **MODERATE PROBABILITY OF IMPERSONATION**"
        verdict_color = "warning"
    else:
        verdict = "✅ **LOW PROBABILITY OF IMPERSONATION**"
        verdict_color = "success"
    
    return {
        'match_score': name_similarity,
        'reasons': reasons,
        'verdict': verdict,
        'verdict_color': verdict_color
    }

df = get_processed_data()

# Filter out removed accounts
df = filter_removed_accounts(df)

def find_duplicate_images(df):
    image_groups = df.groupby('image_hash')['screen_name'].apply(list).to_dict()
    return {k: v for k, v in image_groups.items() if len(v) > 1 and k is not None}

def find_similar_names(df, target_name, threshold=70):
    similar = []
    for idx, row in df.iterrows():
        if pd.isna(row['name']) or pd.isna(target_name): continue
        similarity = fuzz.ratio(str(target_name).lower(), str(row['name']).lower())
        if similarity >= threshold and row['name'] != target_name:
            similar.append({'screen_name': row['screen_name'], 'name': row['name'], 'similarity': similarity, 'image': row['image'], 'risk_score': row['risk_score']})
    return sorted(similar, key=lambda x: x['similarity'], reverse=True)

def generate_pdf_report(flagged_df, report_type, df):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=20, alignment=TA_CENTER)
    story.append(Paragraph(f"Forensic Report: {report_type}", title_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Generated by Officer: {st.session_state['officer_id']}", styles['Normal']))
    story.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d')}", styles['Normal']))
    story.append(Spacer(1, 24))

    # Simplified Table for PDF
    data = [['Handle', 'Name', 'Score', 'Status']]
    for _, row in flagged_df.head(20).iterrows():
        data.append([row['screen_name'], row['name'], row['risk_score'], row['risk_category']])
    
    t = Table(data, colWidths=[1.5*inch, 2*inch, 0.8*inch, 1.2*inch])
    t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.grey), ('GRID', (0,0), (-1,-1), 1, colors.black)]))
    story.append(t)
    
    doc.build(story)
    buffer.seek(0)
    return buffer

def show_account_detail(row, df):
    st.subheader(f"🔍 Detailed Analysis: @{row['screen_name']}")
    col1, col2 = st.columns([1, 2])
    with col1:
        st.image(row['image'], width=250)
        st.metric("Risk Score", f"{row['risk_score']}/100")
        
        # Report Button Section
        st.divider()
        report_count = get_report_count(row['screen_name'])
        is_removed = row['screen_name'] in st.session_state["removed_accounts"]
        
        if is_removed:
            st.error("🗑️ ACCOUNT REMOVED")
        elif row['risk_score'] == 100:
            st.warning(f"Reports: {report_count}/{REPORT_THRESHOLD}")
            if st.button(f"🚨 Report as 100% Fake", key=f"report_{row['screen_name']}"):
                removed = report_account(row['screen_name'])
                if removed:
                    st.success(f"✅ Account @{row['screen_name']} has been REMOVED from dataset!")
                    st.balloons()
                    st.rerun()
                else:
                    st.info(f"Report recorded. {REPORT_THRESHOLD - get_report_count(row['screen_name'])} more needed to remove.")
                    st.rerun()
        else:
            st.info("Only 100% fake accounts can be reported")
            
    with col2:
        st.markdown(f"**Display Name:** {row['name']}\n\n**Account Age:** {row.get('age_days', 'N/A')} days")
        st.markdown(f"**Followers:** {row['followers_count']:,} | **Following:** {row['friends_count']:,}")
        st.warning(f"**Risk Factors:** {row['risk_reasons']}")

# --- 4. OFFICER DASHBOARD UI ---
with st.sidebar:
    st.title("🛡️ Control Center")
    st.write(f"**Officer:** {st.session_state['officer_id']}")
    if st.button("Logout"):
        st.session_state["authenticated"] = False
        st.rerun()
    st.divider()
    st.info("Forensic Engine Active")
    
    # Reporting Statistics
    st.divider()
    st.subheader("📊 Report Stats")
    st.metric("Accounts Reported", len(st.session_state["reported_accounts"]))
    st.metric("Accounts Removed", len(st.session_state["removed_accounts"]))
    st.metric("Report Threshold", REPORT_THRESHOLD)
    
    if st.session_state["reported_accounts"]:
        with st.expander("View Reported Accounts"):
            for acc, count in st.session_state["reported_accounts"].items():
                status = "🗑️ REMOVED" if acc in st.session_state["removed_accounts"] else f"⚠️ {count}/{REPORT_THRESHOLD}"
                st.write(f"**@{acc}**: {status}")

st.title("🕵️ Thread Hunters: Advanced Detection")
st.markdown(f"**Secure Session:** Active for {st.session_state['officer_id']}")

tab_ana, tab_lens, tab_dup, tab_reg, tab_rep, tab_detail = st.tabs([
    "📊 Global Analytics", "🔍 Forensic Lens", "👥 Duplicates", "🕵️ Evidence Registry", "📄 Reports", "🔬 Deep Dive"
])

# --- TAB 1: ANALYTICS ---
with tab_ana:
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Scanned", len(df))
    c2.metric("High Risk", len(df[df['risk_category'] == 'High Risk']))
    c3.metric("Confirmed Fakes", len(df[df['dataset'] == 'FAKE']))
    
    fig = px.scatter(df, x="friends_count", y="followers_count", color="risk_category",
                     size="risk_score", hover_name="screen_name", log_x=True, log_y=True,
                     title="Behavioral Mapping", color_discrete_map={'High Risk': '#FF4B4B', 'Medium Risk': '#FFAB00', 'Low Risk': '#0068C9'})
    st.plotly_chart(fig, use_container_width=True)

# --- TAB 2: FORENSIC LENS (ENHANCED) ---
with tab_lens:
    st.subheader("🔍 Impersonation Analysis Engine")
    
    col_t, col_s = st.columns(2)
    with col_t:
        target_un = st.selectbox("Official Reference:", df['screen_name'].unique(), index=1)
        target = df[df['screen_name'] == target_un].iloc[0]
        st.image(target['image'], width=150)
        st.caption(f"@{target['screen_name']}")
        st.caption(f"**{target['name']}**")
        
    with col_s:
        suspect_un = st.selectbox("Suspect:", df['screen_name'].unique(), index=0)
        suspect = df[df['screen_name'] == suspect_un].iloc[0]
        st.image(suspect['image'], width=150)
        st.caption(f"@{suspect['screen_name']}")
        st.caption(f"**{suspect['name']}**")
    
    st.divider()
    
    # Perform impersonation analysis
    analysis = analyze_impersonation_match(target, suspect)
    
    # Display match score
    col_score, col_verdict = st.columns([1, 2])
    with col_score:
        st.metric("Impersonation Match", f"{analysis['match_score']}%")
        st.progress(analysis['match_score']/100)
    
    with col_verdict:
        if analysis['verdict_color'] == 'error':
            st.error(analysis['verdict'])
        elif analysis['verdict_color'] == 'warning':
            st.warning(analysis['verdict'])
        else:
            st.success(analysis['verdict'])
    
    # Display detailed analysis
    st.divider()
    st.subheader("📋 Detailed Forensic Analysis")
    
    for reason in analysis['reasons']:
        st.markdown(reason)
    
    # Comparison table
    st.divider()
    st.subheader("📊 Account Comparison")
    
    comparison_data = {
        'Metric': ['Display Name', 'Risk Score', 'Account Age (days)', 'Followers', 'Following', 'Posts', 'Default Profile'],
        'Official Reference': [
            target['name'],
            f"{target['risk_score']}/100",
            target.get('age_days', 'N/A'),
            f"{target['followers_count']:,}",
            f"{target['friends_count']:,}",
            target['statuses_count'],
            'Yes' if target['default_profile'] == 1.0 else 'No'
        ],
        'Suspect Account': [
            suspect['name'],
            f"{suspect['risk_score']}/100",
            suspect.get('age_days', 'N/A'),
            f"{suspect['followers_count']:,}",
            f"{suspect['friends_count']:,}",
            suspect['statuses_count'],
            'Yes' if suspect['default_profile'] == 1.0 else 'No'
        ]
    }
    
    comparison_df = pd.DataFrame(comparison_data)
    st.dataframe(comparison_df, use_container_width=True, hide_index=True)

# --- TAB 3: DUPLICATES ---
with tab_dup:
    st.subheader("👥 Duplicate Profile Image Detection")
    duplicates = find_duplicate_images(df)
    
    if duplicates:
        st.warning(f"Found {len(duplicates)} groups of accounts using identical profile images")
        
        for img_hash, accounts in list(duplicates.items())[:10]:  # Show first 10 groups
            with st.expander(f"🚨 {len(accounts)} accounts sharing the same image"):
                cols = st.columns(min(len(accounts), 4))
                for idx, account_name in enumerate(accounts):
                    account_row = df[df['screen_name'] == account_name].iloc[0]
                    with cols[idx % 4]:
                        st.image(account_row['image'], width=150)
                        st.write(f"**@{account_name}**")
                        st.write(f"Risk: {account_row['risk_score']}")
    else:
        st.success("No duplicate profile images detected")
    
    st.divider()
    st.subheader("🔍 Similar Name Detection")
    search_name = st.text_input("Search for similar account names:", "")
    
    if search_name:
        similar = find_similar_names(df, search_name, threshold=70)
        if similar:
            st.warning(f"Found {len(similar)} accounts with similar names")
            for acc in similar[:10]:
                col1, col2, col3 = st.columns([1, 2, 1])
                with col1:
                    st.image(acc['image'], width=100)
                with col2:
                    st.write(f"**@{acc['screen_name']}** - {acc['name']}")
                    st.write(f"Similarity: {acc['similarity']}%")
                with col3:
                    st.metric("Risk", acc['risk_score'])
        else:
            st.info("No similar names found")

# --- TAB 4: EVIDENCE REGISTRY ---
with tab_reg:
    st.subheader("🕵️ Evidence Registry")
    
    # Filter options
    col_f1, col_f2 = st.columns(2)
    with col_f1:
        show_filter = st.selectbox("Filter by:", ["All Accounts", "100% Fake Only", "High Risk Only"])
    with col_f2:
        sort_by = st.selectbox("Sort by:", ["Risk Score (High to Low)", "Risk Score (Low to High)", "Screen Name"])
    
    # Apply filters
    filtered_df = df.copy()
    if show_filter == "100% Fake Only":
        filtered_df = filtered_df[filtered_df['risk_score'] == 100]
    elif show_filter == "High Risk Only":
        filtered_df = filtered_df[filtered_df['risk_category'] == 'High Risk']
    
    # Apply sorting
    if sort_by == "Risk Score (High to Low)":
        filtered_df = filtered_df.sort_values('risk_score', ascending=False)
    elif sort_by == "Risk Score (Low to High)":
        filtered_df = filtered_df.sort_values('risk_score', ascending=True)
    else:
        filtered_df = filtered_df.sort_values('screen_name')
    
    # Add report count column
    filtered_df['reports'] = filtered_df['screen_name'].apply(lambda x: f"{get_report_count(x)}/{REPORT_THRESHOLD}")
    
    st.dataframe(
        filtered_df[['image', 'screen_name', 'name', 'risk_score', 'risk_category', 'reports', 'dataset']], 
        column_config={
            "image": st.column_config.ImageColumn("Profile"),
            "reports": st.column_config.TextColumn("Reports")
        }, 
        use_container_width=True
    )
    
    # Bulk reporting for 100% fake accounts
    st.divider()
    fake_100_accounts = df[df['risk_score'] == 100]
    unreported_100 = fake_100_accounts[~fake_100_accounts['screen_name'].isin(st.session_state["removed_accounts"])]
    
    if len(unreported_100) > 0:
        st.warning(f"⚠️ {len(unreported_100)} accounts detected with 100% fake score")
        if st.button("🚨 Report All 100% Fake Accounts"):
            removed_count = 0
            for _, row in unreported_100.iterrows():
                if report_account(row['screen_name']):
                    removed_count += 1
            st.success(f"✅ Processed {len(unreported_100)} accounts. {removed_count} removed from dataset.")
            st.rerun()
    else:
        st.success("✅ No unreported 100% fake accounts found")

# --- TAB 5: REPORT GENERATOR ---
with tab_rep:
    report_type = st.radio("Target Data:", ["High Risk Accounts", "Confirmed Fakes"])
    if st.button("Generate Officer Report"):
        flagged = df[df['risk_category'] == 'High Risk'] if "Risk" in report_type else df[df['dataset'] == 'FAKE']
        pdf = generate_pdf_report(flagged, report_type, df)
        st.download_button("Download Official PDF", data=pdf, file_name="Forensic_Report.pdf", mime="application/pdf")

# --- TAB 6: ACCOUNT DETAILS ---
with tab_detail:
    selected_username = st.selectbox("Select Account for Deep Investigation:", options=df['screen_name'].tolist())
    if selected_username:
        show_account_detail(df[df['screen_name'] == selected_username].iloc[0], df)

st.divider()
st.caption(f"Logged in as {st.session_state['officer_id']} | Session ID: {hash(st.session_state['officer_id'])}")
