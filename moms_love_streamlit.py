# moms_love_streamlit.py
"""
Mom's Love - Streamlit Single-file App (fixed session handling)

Run:
    pip install streamlit sqlmodel passlib[bcrypt] qrcode[pil]
    streamlit run moms_love_streamlit.py
"""
import streamlit as st
from sqlmodel import SQLModel, Field, Session, create_engine, select
from typing import Optional, List
from enum import Enum
import time, uuid, math, secrets, io, random, base64
from passlib.context import CryptContext
import qrcode
import os
# -------------------------------
# Config / Secrets (dev)
# -------------------------------
JWT_SECRET_KEY = "CHANGE_ME_NOW"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
DB_FILE = "moms_love_streamlit.db"
engine = create_engine(f"sqlite:///{DB_FILE}", echo=False)

# -------------------------------
# Models
# -------------------------------
class Role(str, Enum):
    CUSTOMER = "customer"
    COOK = "cook"
    DELIVERY = "delivery_agent"

class User(SQLModel, table=True):
    __table_args__ = {"extend_existing": True}  # <-- Add this
    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), index=True)
    name: str
    role: Role
    phone: Optional[str] = None
    email: Optional[str] = None
    password_hash: Optional[str] = None
    address: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    cook_badge: Optional[str] = None
    is_verified: bool = False
    phone_verified: bool = False
    identity_doc: Optional[str] = None
    bank_vpa: Optional[str] = None

class Meal(SQLModel, table=True):
    __table_args__ = {"extend_existing": True}  # <-- Add this
    id: Optional[int] = Field(default=None, primary_key=True)
    cook_id: int = Field(foreign_key="user.id")
    title: str
    description: Optional[str] = None
    price: float = 0.0
    secret_family_recipe: bool = False
    available: bool = True

class OrderStatus(str, Enum):
    PLACED = "placed"
    PAID = "paid"
    ACCEPTED_BY_COOK = "accepted_by_cook"
    DELIVERY_ASSIGNED = "delivery_assigned"
    PICKED_UP = "picked_up"
    DELIVERED = "delivered"
    CANCELLED = "cancelled"

class Order(SQLModel, table=True):
    __table_args__ = {"extend_existing": True}  # <-- Add this
    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), index=True)
    customer_id: int = Field(foreign_key="user.id")
    meal_id: int = Field(foreign_key="meal.id")
    cook_id: int = Field(foreign_key="user.id")
    status: OrderStatus = OrderStatus.PLACED
    price: float = 0.0
    placed_at: float = Field(default_factory=time.time)
    accepted_at: Optional[float] = None
    assigned_delivery_id: Optional[int] = None
    picked_up_at: Optional[float] = None
    delivered_at: Optional[float] = None
    paid: bool = False
    payment_ref: Optional[str] = None

# -------------------------------
# Init DB
# -------------------------------
def init_db():
    SQLModel.metadata.create_all(engine)

init_db()

# -------------------------------
# Utilities
# -------------------------------
notifications = {}  # user_id -> list[str]
otp_store = {}  # phone -> (otp, expiry)

def add_notification(user_id: int, msg: str):
    notifications.setdefault(user_id, []).append(msg)

def get_notifications(user_id: int):
    return notifications.pop(user_id, [])

def haversine(lat1, lon1, lat2, lon2):
    R = 6371
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
    c = 2*math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c

# Password helpers
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# OTP (Fast2SMS) stub - replace send_sms with Fast2SMS API later
def send_otp_sms(phone: str, dev_mode: bool = True):
    otp = f"{random.randint(100000,999999)}"
    expiry = time.time() + 5*60
    otp_store[phone] = (otp, expiry)
    if dev_mode:
        return otp
    # TODO: integrate Fast2SMS here using API key
    return None

def verify_otp(phone: str, otp: str):
    rec = otp_store.get(phone)
    if not rec:
        return False, 'no otp requested'
    stored, expiry = rec
    if time.time() > expiry:
        otp_store.pop(phone, None)
        return False, 'otp expired'
    if stored != otp:
        return False, 'invalid otp'
    otp_store.pop(phone, None)
    return True, 'verified'

# -------------------------------
# Payment / UPI intent helper (avoid DetachedInstanceError)
# -------------------------------
def create_upi_intent(order_id: int, payee_vpa: str, payee_name: Optional[str], dev_mode: bool = True):
    """
    Safely create UPI intent and return existing QR code from PaymentQR.JPG in the same folder.
    """
    payment_ref = f"upi_{secrets.token_hex(8)}"
    
    # Acquire order and update inside session
    with Session(engine) as session:
        order = session.get(Order, order_id)
        if not order:
            return None
        order.payment_ref = payment_ref
        session.add(order)
        session.commit()
        # copy needed primitives
        order_uuid = order.uuid
        order_price = order.price

    # Create UPI intent
    tn = f"Mom's Love order {order_uuid}"
    am = f"{order_price:.2f}"
    pa = payee_vpa
    pn = (payee_name or "Mom's Love").replace(' ', '+')
    upi_uri = f"upi://pay?pa={pa}&pn={pn}&tn={tn.replace(' ', '+')}&am={am}&cu=INR&tr={payment_ref}"
    
    # Read existing QR image instead of generating one
    qr_path = os.path.join(os.path.dirname(__file__), "PaymentQR.JPG")
    if not os.path.exists(qr_path):
        raise FileNotFoundError(f"QR code file not found: {qr_path}")
    
    with open(qr_path, "rb") as f:
        qr_b64 = base64.b64encode(f.read()).decode()

    return {
        "upi_uri": upi_uri,
        "payment_ref": payment_ref,
        "qr_base64": qr_b64,
        "amount": order_price,
        "order_uuid": order_uuid
    }

def verify_payment_mock(order_id: int, payment_ref: str):
    """
    Mock verification safely — do session updates inside the session and copy primitives out for notifications.
    """
    with Session(engine) as session:
        order = session.get(Order, order_id)
        if not order:
            return False, 'order not found'
        if order.payment_ref != payment_ref:
            return False, 'payment_ref mismatch'
        order.paid = True
        order.status = OrderStatus.PAID
        session.add(order)
        session.commit()
        # copy primitives for notifications
        cook_id = order.cook_id
        customer_id = order.customer_id
        order_uuid = order.uuid

    add_notification(cook_id, f"Order {order_uuid} paid. Please prepare the meal.")
    add_notification(customer_id, f"Order {order_uuid} payment received. Waiting for cook to accept.")
    return True, 'verified'

# Delivery assignment (safe)
def assign_nearest_delivery(order_id: int):
    with Session(engine) as session:
        order = session.get(Order, order_id)
        if not order:
            return False
        cook = session.get(User, order.cook_id)
        if not (cook and cook.lat and cook.lon):
            add_notification(order.customer_id, f"Order {order.uuid}: Cook location not available.")
            return False
        agents = session.exec(select(User).where(User.role == Role.DELIVERY)).all()
        candidates = []
        for a in agents:
            if a.lat is None or a.lon is None:
                continue
            dist = haversine(cook.lat, cook.lon, a.lat, a.lon)
            candidates.append((dist, a))
        if not candidates:
            add_notification(order.customer_id, f"Order {order.uuid}: No delivery agents available currently.")
            return False
        candidates.sort(key=lambda x: x[0])
        nearest = candidates[0][1]
        order.assigned_delivery_id = nearest.id
        order.status = OrderStatus.DELIVERY_ASSIGNED
        order.accepted_at = order.accepted_at or time.time()
        session.add(order)
        session.commit()
        # copy primitives
        order_uuid = order.uuid
        dist_km = candidates[0][0]
        cook_id = cook.id
        customer_id = order.customer_id
        nearest_id = nearest.id

    add_notification(nearest_id, f"New pickup assigned: order {order_uuid} from cook {cook.name} at {cook.address}")
    add_notification(customer_id, f"Delivery agent {nearest.name} assigned for order {order_uuid} (approx {dist_km:.1f} km from cook)")
    add_notification(cook_id, f"Delivery agent {nearest.name} assigned to pick up your order {order_uuid}")
    return True

# -------------------------------
# Seed demo data (safe updates)
# -------------------------------
with Session(engine) as session:
    users = session.exec(select(User)).all()
    if not users:
        cook1 = User(name="Asha Devi", role=Role.COOK, phone="+91-9000000000", address="Naxalbari, Siliguri", lat=26.7, lon=88.4, cook_badge="Gourmet", is_verified=False, bank_vpa="asha@upi")
        customer = User(name="Subham", role=Role.CUSTOMER, phone="+91-9000000001", email="subham@example.com")
        agent = User(name="Ravi", role=Role.DELIVERY, phone="+91-9000000002", lat=26.71, lon=88.41)
        session.add_all([cook1, customer, agent])
        session.commit()
        # create meal for cook1
        session.add(Meal(cook_id=cook1.id, title="Mushroom Delight Thali", description="Locally grown gourmet mushroom thali.", price=199.0, secret_family_recipe=True))
        session.commit()

# -------------------------------
# Streamlit UI
# -------------------------------
st.set_page_config(page_title="Mom's Love", layout="wide")

if 'current_user' not in st.session_state:
    st.session_state['current_user'] = None

def refresh():
    st.rerun()

# Sidebar / Auth
with st.sidebar:
    st.title("Mom's Love")
    if st.session_state.current_user is None:
        tab = st.radio("I am:", ("Visitor", "Customer", "Cook", "Delivery", "Admin"))
        if tab == "Visitor":
            st.write("Please register or login from the main page.")
        else:
            st.write(f"Register / Login as {tab}")
    else:
        user = st.session_state.current_user
        st.write(f"Logged in as: {user['name']} ({user['role']})")
        if st.button("Logout", key="logout_btn"):
            st.session_state.current_user = None
            refresh()

page = st.selectbox("Go to:", ["Home", "Register", "Login", "Cook Onboard", "Marketplace", "My Orders", "Admin Panel", "Notifications"])

# -------------------------------
# Home
# -------------------------------
if page == "Home":
    st.header("Welcome to Mom's Love")
    st.write("A marketplace for home cooks to sell home-cooked food. Use the Register page to get started.")

# -------------------------------
# Register
# -------------------------------
elif page == "Register":
    st.header("Register")
    with st.form("reg_form", clear_on_submit=True):
        role = st.selectbox("Role", [Role.CUSTOMER.value, Role.COOK.value, Role.DELIVERY.value])
        name = st.text_input("Full name")
        email = st.text_input("Email")
        phone = st.text_input("Phone (with country code)")
        password = st.text_input("Password", type="password")
        address = st.text_input("Address (optional)")
        lat = st.text_input("Latitude (optional)")
        lon = st.text_input("Longitude (optional)")
        submitted = st.form_submit_button("Register")
        if submitted:
            with Session(engine) as session:
                existing = session.exec(select(User).where(User.email == email)).first() if email else None
                if existing:
                    st.error("Email already registered")
                else:
                    hashed = get_password_hash(password)
                    user = User(name=name, email=email or None, password_hash=hashed, role=Role(role), phone=phone or None, address=address or None, lat=float(lat) if lat else None, lon=float(lon) if lon else None)
                    session.add(user)
                    session.commit()
                    st.success("Registered successfully. Please login.")

# -------------------------------
# Login
# -------------------------------
elif page == "Login":
    st.header("Login")
    with st.form("login_form", clear_on_submit=True):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        if submitted:
            with Session(engine) as session:
                user = session.exec(select(User).where(User.email == email)).first()
                if not user or not user.password_hash or not verify_password(password, user.password_hash):
                    st.error("Invalid credentials")
                else:
                    # copy safe primitives into session_state
                    st.session_state.current_user = {"id": user.id, "name": user.name, "role": user.role.value}
                    st.success(f"Welcome {user.name}")
                    refresh()

# -------------------------------
# Cook Onboard
# -------------------------------
elif page == "Cook Onboard":
    st.header("Cook Onboarding")
    st.write("Create your cook profile and upload identity details. An admin will review and verify you.")
    with st.form("cook_form", clear_on_submit=True):
        name = st.text_input("Full name")
        email = st.text_input("Email")
        phone = st.text_input("Phone (with country code)")
        password = st.text_input("Choose a password", type="password")
        address = st.text_input("Address")
        lat = st.text_input("Latitude (optional)")
        lon = st.text_input("Longitude (optional)")
        identity_doc = st.text_area("Identity details or notes (paste ID text or description)")
        bank_vpa = st.text_input("Bank / UPI VPA (for payouts)")
        submitted = st.form_submit_button("Register as Cook")
        if submitted:
            with Session(engine) as session:
                existing = session.exec(select(User).where(User.email == email)).first() if email else None
                if existing:
                    st.error("Email already registered")
                else:
                    hashed = get_password_hash(password)
                    cook = User(name=name, email=email or None, password_hash=hashed, role=Role.COOK, phone=phone or None, address=address or None, lat=float(lat) if lat else None, lon=float(lon) if lon else None, identity_doc=identity_doc or None, bank_vpa=bank_vpa or None, is_verified=False)
                    session.add(cook)
                    session.commit()
                    # copy primitive id for notification
                    cook_id = cook.id
            add_notification(0, f"New cook registration: {name} (id {cook_id}). Review identity_doc.")
            st.success("Cook registration submitted. Admin will review your identity documents.")

# -------------------------------
# Marketplace
# -------------------------------
elif page == "Marketplace":
    st.header("Marketplace - Available Meals")
    # fetch meals and copy minimal cook info for display
    with Session(engine) as session:
        meals = session.exec(select(Meal).where(Meal.available == True)).all()
        meal_rows = []
        for m in meals:
            cook = session.get(User, m.cook_id)
            meal_rows.append({
                "meal_id": m.id,
                "title": m.title,
                "desc": m.description,
                "price": m.price,
                "cook_id": cook.id if cook else None,
                "cook_name": cook.name if cook else "Unknown",
                "cook_verified": cook.is_verified if cook else False,
                "cook_bank_vpa": cook.bank_vpa if cook else None
            })

    for m in meal_rows:
        st.subheader(m["title"] + f" — ₹{m['price']:.2f}")
        st.write(m["desc"])
        st.write(f"Cook: {m['cook_name']} {'(verified)' if m['cook_verified'] else '(unverified)'}")
        cols = st.columns([1,1,2])
        if cols[0].button(f"Order_{m['meal_id']}", key=f"order_btn_{m['meal_id']}"):
            # place order (safe session)
            if st.session_state.current_user is None or st.session_state.current_user['role'] != Role.CUSTOMER.value:
                st.warning("Please login as a customer to place orders.")
            else:
                customer_id = st.session_state.current_user['id']
                with Session(engine) as session:
                    order = Order(customer_id=customer_id, meal_id=m["meal_id"], cook_id=m["cook_id"], price=m["price"])
                    session.add(order)
                    session.commit()
                    # copy primitives for notification and message
                    order_uuid = order.uuid
                    cook_id = order.cook_id
                add_notification(cook_id, f"New order {order_uuid} placed for {m['title']}. Please accept or reject.")
                st.success(f"Order {order_uuid} placed. Please proceed to payment to confirm.")
        if cols[1].button(f"ViewCook_{m['cook_id']}", key=f"view_cook_{m['cook_id']}"):
            # display cook details — use session to read
            with Session(engine) as session:
                cook = session.get(User, m["cook_id"])
                if cook:
                    # copy primitives
                    cook_name = cook.name
                    cook_address = cook.address
                    cook_verified = cook.is_verified
                    cook_bank_vpa = cook.bank_vpa
            st.info(f"Cook: {cook_name}\nAddress: {cook_address}\nVerified: {cook_verified}\nBank VPA: {cook_bank_vpa}")

# -------------------------------
# My Orders
# -------------------------------
elif page == "My Orders":
    st.header("My Orders")
    if st.session_state.current_user is None:
        st.warning("Please login to view your orders.")
    else:
        uid = st.session_state.current_user['id']
        with Session(engine) as session:
            orders = session.exec(select(Order).where(Order.customer_id == uid)).all()
            # copy order list to primitives
            orders_data = []
            for o in orders:
                meal = session.get(Meal, o.meal_id)
                orders_data.append({
                    "order_id": o.id,
                    "order_uuid": o.uuid,
                    "meal_title": meal.title if meal else "Unknown",
                    "price": o.price,
                    "paid": o.paid
                })

        if not orders_data:
            st.info("No orders yet")
        for o in orders_data:
            st.write(f"Order {o['order_uuid']} — {o['meal_title']} — ₹{o['price']:.2f} — Paid: {o['paid']}")
            if not o['paid']:
                if st.button(f"Pay_Order_{o['order_id']}", key=f"pay_btn_{o['order_id']}"):
                    # create upi intent safely
                    # need cook bank_vpa from DB
                    with Session(engine) as session:
                        order_obj = session.get(Order, o['order_id'])
                        cook_obj = session.get(User, order_obj.cook_id) if order_obj else None
                        payee = cook_obj.bank_vpa if cook_obj and cook_obj.bank_vpa else "moms_love@upi"
                    res = create_upi_intent(o['order_id'], payee, cook_obj.name if cook_obj else None)
                    if res:
                        st.write("Scan this UPI QR or open with a UPI app:")
                        st.image(base64.b64decode(res['qr_base64']))
                        st.write(res['upi_uri'])
                        payment_ref = st.text_input(f"Payment ref for order {o['order_id']}", key=f"payref_{o['order_id']}")
                        if st.button(f"Verify_payment_{o['order_id']}", key=f"verify_{o['order_id']}"):
                            ok, msg = verify_payment_mock(o['order_id'], payment_ref)
                            if ok:
                                st.success("Payment verified")
                            else:
                                st.error(msg)

# -------------------------------
# Notifications
# -------------------------------
elif page == "Notifications":
    st.header("Notifications")
    if st.session_state.current_user is None:
        st.warning("Please login to see notifications")
    else:
        nid = st.session_state.current_user['id']
        notes = get_notifications(nid)
        if not notes:
            st.info("No notifications")
        else:
            for n in notes:
                st.write("- ", n)

# -------------------------------
# Admin Panel (keys added for buttons)
# -------------------------------
elif page == "Admin Panel":
    st.header("Admin Panel")
    st.write("This panel shows pending cook registrations. Approve or reject cooks here.")
    admin_pw = st.text_input("Admin password", type="password")
    if admin_pw != "admin":
        st.warning("Enter admin password (demo: 'admin') to access admin features")
    else:
        with Session(engine) as session:
            pending = session.exec(select(User).where(User.role == Role.COOK).where(User.is_verified == False)).all()
            # copy minimal list of pending cook primitives for safe iteration
            pending_rows = [{"id": p.id, "name": p.name, "email": p.email, "phone": p.phone, "address": p.address, "identity_doc": p.identity_doc, "bank_vpa": p.bank_vpa, "cook_badge": p.cook_badge} for p in pending]

        if not pending_rows:
            st.info("No pending cooks")
        for idx, p in enumerate(pending_rows):
            st.subheader(p["name"])
            st.write(f"Email: {p['email']}")
            st.write(f"Phone: {p['phone']}")
            st.write(f"Address: {p['address']}")
            st.write(f"Badge: {p['cook_badge'] or 'N/A'}")
            st.write(f"VPA: {p['bank_vpa']}")
            col1, col2, col3 = st.columns([1,1,2])
            with col1:
                if st.button("Approve", key=f"approve_{p['id']}_{idx}"):
                    with Session(engine) as session:
                        cook = session.get(User, p["id"])
                        if cook:
                            cook.is_verified = True
                            session.add(cook)
                            session.commit()
                            st.success(f"Cook {p['name']} approved ✅")
                            add_notification(p["id"], "Your cook profile has been approved by admin.")
                            refresh()
            with col2:
                if st.button("Reject", key=f"reject_{p['id']}_{idx}"):
                    with Session(engine) as session:
                        cook = session.get(User, p["id"])
                        if cook:
                            session.delete(cook)
                            session.commit()
                            st.warning(f"Cook {p['name']} rejected ❌")
                            add_notification(0, f"Cook {p['name']} rejected and removed")
                            refresh()
            with col3:
                msg_key = f"msg_{p['id']}_{idx}"
                msg = st.text_input("Message to cook", key=msg_key)
                if st.button("Send Message", key=f"sendmsg_{p['id']}_{idx}"):
                    add_notification(p["id"], msg)
                    st.success("Message sent")
            st.divider()

# -------------------------------
# Cook actions: create meal (only for logged-in cooks)
# -------------------------------
# Use query params to trigger create meal flow
params = st.query_params
if st.session_state.current_user and st.session_state.current_user['role'] == Role.COOK.value:
    st.sidebar.markdown("---")
    st.sidebar.subheader("Cook actions")
    if st.sidebar.button("Create Meal", key="sidebar_create_meal"):
        st.set_query_params(_create_meal="1")

if st.query_params.get('_create_meal') == ["1"]:
    if st.session_state.current_user and st.session_state.current_user['role'] == Role.COOK.value:
        st.header("Create Meal")
        with st.form("create_meal_form", clear_on_submit=True):
            title = st.text_input("Title")
            desc = st.text_area("Description")
            price = st.number_input("Price", min_value=1.0, value=100.0)
            secret = st.checkbox("Secret family recipe (visible only after purchase)")
            submitted = st.form_submit_button("Create")
            if submitted:
                with Session(engine) as session:
                    meal = Meal(cook_id=st.session_state.current_user['id'], title=title, description=desc, price=price, secret_family_recipe=secret)
                    session.add(meal)
                    session.commit()
                st.success("Meal created")
                st.set_query_params()  # clear query params
                refresh()
    else:
        st.warning("Only logged in cooks can create meals")

# Footer
st.sidebar.markdown("---")
st.sidebar.write("Demo app — replace SMS and payments with real providers when ready.")
