from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, UploadFile, File, Form, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import BackgroundTasks
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr, field_validator
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt
import bcrypt
import razorpay
import requests
from decimal import Decimal
import re
import smtplib
from email.message import EmailMessage

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

# Razorpay Configuration (will be set by user later)
RAZORPAY_KEY_ID = os.environ.get('RAZORPAY_KEY_ID', '')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET', '')

# Shiprocket Configuration (will be set by user later)
SHIPROCKET_EMAIL = os.environ.get('SHIPROCKET_EMAIL', '')
SHIPROCKET_PASSWORD = os.environ.get('SHIPROCKET_PASSWORD', '')

# SMTP Configuration (Zoho)
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM_EMAIL = os.environ.get("SMTP_FROM_EMAIL")
SMTP_FROM_NAME = os.environ.get("SMTP_FROM_NAME", "ZENVY")

app = FastAPI()

# Rate Limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

api_router = APIRouter(prefix="/api")
security = HTTPBearer()

# Password validation regex
PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')

# ============ MODELS ============

class Product(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    price: float
    discount: float = 0
    stock: int
    images: List[str]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ProductCreate(BaseModel):
    name: str
    description: str
    price: float
    discount: float = 0
    stock: int
    images: List[str]

class ProductUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    discount: Optional[float] = None
    stock: Optional[int] = None
    images: Optional[List[str]] = None

class OrderItem(BaseModel):
    product_id: str
    product_name: str
    price: float
    quantity: int
    image: str

class Order(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    order_number: str = Field(default_factory=lambda: f"ORD-{uuid.uuid4().hex[:8].upper()}")
    customer_name: str
    customer_email: EmailStr
    customer_phone: str
    shipping_address: str
    shipping_city: str
    shipping_state: str
    shipping_pincode: str
    items: List[OrderItem]
    subtotal: float
    shipping_cost: float = 0
    total: float
    payment_id: Optional[str] = None
    razorpay_order_id: Optional[str] = None
    razorpay_payment_id: Optional[str] = None
    razorpay_signature: Optional[str] = None
    payment_status: str = "pending"  # pending, paid, failed
    order_status: str = "pending"  # pending, confirmed, packed, shipped, delivered, cancelled
    tracking_id: Optional[str] = None
    shiprocket_order_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class OrderCreate(BaseModel):
    customer_name: str
    customer_email: EmailStr
    customer_phone: str
    shipping_address: str
    shipping_city: str
    shipping_state: str
    shipping_pincode: str
    items: List[OrderItem]
    subtotal: float
    total: float

class OrderStatusUpdate(BaseModel):
    order_status: str
    tracking_id: Optional[str] = None

class PaymentVerification(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str

class Admin(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    password_hash: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AdminLogin(BaseModel):
    username: str
    password: str

class AdminCreate(BaseModel):
    username: str
    password: str
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[@$!%*?&]', v):
            raise ValueError('Password must contain at least one special character (@$!%*?&)')
        return v

# ============ HELPER FUNCTIONS ============

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def send_email(to_email: str, subject: str, html_content: str):
    if not all([SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM_EMAIL]):
        logging.warning("SMTP not fully configured, email skipped")
        return

    msg = EmailMessage()
    msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content("This email requires HTML support.")
    msg.add_alternative(html_content, subtype="html")

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
            logging.info(f"Email sent to {to_email}")
    except Exception as e:
        logging.error(f"Email sending failed: {e}")

def order_confirmation_email(order: dict) -> str:
    items_html = ""
    for item in order["items"]:
        items_html += f"""
        <tr>
            <td>{item['product_name']}</td>
            <td>{item['quantity']}</td>
            <td>₹{item['price']}</td>
        </tr>
        """

    return f"""
    <html>
    <body style="font-family: Arial, sans-serif;">
        <h2>Thank you for your order, {order['customer_name']}!</h2>
        <p><strong>Order Number:</strong> {order['order_number']}</p>

        <table border="1" cellpadding="8" cellspacing="0">
            <tr>
                <th>Product</th>
                <th>Qty</th>
                <th>Price</th>
            </tr>
            {items_html}
        </table>

        <p><strong>Total:</strong> ₹{order['total']}</p>

        <p>We’ll notify you when your order is shipped.</p>

        <p>— Team ZENVY</p>
    </body>
    </html>
    """

# ============ PUBLIC ROUTES ============

@api_router.get("/")
async def root():
    return {"message": "E-Commerce API", "status": "active"}

# Product Routes
@api_router.get("/products", response_model=List[Product])
async def get_products(
    search: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    limit: int = 100
):
    query = {}
    if search:
        query["name"] = {"$regex": search, "$options": "i"}
    if min_price is not None or max_price is not None:
        query["price"] = {}
        if min_price is not None:
            query["price"]["$gte"] = min_price
        if max_price is not None:
            query["price"]["$lte"] = max_price
    
    products = await db.products.find(query, {"_id": 0}).limit(limit).to_list(limit)
    for product in products:
        if isinstance(product.get('created_at'), str):
            product['created_at'] = datetime.fromisoformat(product['created_at'])
        if isinstance(product.get('updated_at'), str):
            product['updated_at'] = datetime.fromisoformat(product['updated_at'])
    return products

@api_router.get("/products/{product_id}", response_model=Product)
async def get_product(product_id: str):
    product = await db.products.find_one({"id": product_id}, {"_id": 0})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    if isinstance(product.get('created_at'), str):
        product['created_at'] = datetime.fromisoformat(product['created_at'])
    if isinstance(product.get('updated_at'), str):
        product['updated_at'] = datetime.fromisoformat(product['updated_at'])
    return product

# Order Routes
@api_router.post("/orders", response_model=Order)
async def create_order(order_data: OrderCreate):
    order = Order(**order_data.model_dump())
    
    # Create Razorpay order if keys are configured
    if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET:
        try:
            razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
            amount_in_paise = int(order.total * 100)
            razorpay_order = razorpay_client.order.create({
                "amount": amount_in_paise,
                "currency": "INR",
                "receipt": order.order_number,
                "payment_capture": 0
            })
            order.razorpay_order_id = razorpay_order['id']
        except Exception as e:
            logging.error(f"Razorpay order creation failed: {e}")
    
    doc = order.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['updated_at'] = doc['updated_at'].isoformat()
    
    await db.orders.insert_one(doc)
    return order

@api_router.post("/orders/verify-payment")
async def verify_payment(
    payment_data: PaymentVerification,
    background_tasks: BackgroundTasks
):
    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        raise HTTPException(status_code=400, detail="Razorpay not configured")
    
    try:
        razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

        # 🔍 DEBUG LOGS (ADD HERE)
        print("---- RAZORPAY VERIFY ----")
        print("ORDER ID:", payment_data.razorpay_order_id)
        print("PAYMENT ID:", payment_data.razorpay_payment_id)
        print("SIGNATURE:", payment_data.razorpay_signature)
        print("KEY ID:", RAZORPAY_KEY_ID)
        print("SECRET PRESENT:", bool(RAZORPAY_KEY_SECRET))
        print("--------------------------")
        
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': payment_data.razorpay_order_id,
            'razorpay_payment_id': payment_data.razorpay_payment_id,
            'razorpay_signature': payment_data.razorpay_signature
        })
        
        # Update order
        await db.orders.update_one(
            {"razorpay_order_id": payment_data.razorpay_order_id},
            {
                "$set": {
                    "payment_status": "paid",
                    "order_status": "confirmed",
                    "razorpay_payment_id": payment_data.razorpay_payment_id,
                    "razorpay_signature": payment_data.razorpay_signature,
                    "updated_at": datetime.now(timezone.utc).isoformat()
                }
            }
        )
        
        # Reduce stock for each item
        order = await db.orders.find_one({"razorpay_order_id": payment_data.razorpay_order_id}, {"_id": 0})
        if order:
            # 📧 Send order confirmation email
            try:
                background_tasks.add_task(
                    send_email,
                    order["customer_email"],
                    f"Order Confirmed - {order['order_number']}",
                    order_confirmation_email(order)
                )
            except Exception as e:
                logging.error(f"Order email failed: {e}")
            for item in order['items']:
                await db.products.update_one(
                    {"id": item['product_id']},
                    {"$inc": {"stock": -item['quantity']}}
                )
            
            # Auto-create Shiprocket shipment if configured
            if SHIPROCKET_EMAIL and SHIPROCKET_PASSWORD:
                try:
                    await create_shiprocket_shipment_internal(order)
                except Exception as e:
                    logging.error(f"Auto-shipment creation failed: {e}")
        
        return {"status": "success", "message": "Payment verified"}
    except Exception as e:
        logging.error(f"Payment verification failed: {e}")
        raise HTTPException(status_code=400, detail="Payment verification failed")

@api_router.get("/orders/track/{order_number}")
async def track_order(order_number: str):
    order = await db.orders.find_one({"order_number": order_number.upper()}, {"_id": 0})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    # Convert ISO strings to datetime
    if isinstance(order.get('created_at'), str):
        order['created_at'] = datetime.fromisoformat(order['created_at'])
    if isinstance(order.get('updated_at'), str):
        order['updated_at'] = datetime.fromisoformat(order['updated_at'])
    
    return order

# Admin Auth Routes
@api_router.post("/admin/login")
@limiter.limit("5/minute")
async def admin_login(request: Request, credentials: AdminLogin):
    admin = await db.admins.find_one({"username": credentials.username}, {"_id": 0})
    if not admin or not verify_password(credentials.password, admin['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": admin['username']})
    return {"access_token": access_token, "token_type": "bearer"}

@api_router.post("/admin/create")
async def create_admin(admin_data: AdminCreate):
    # Check if admin already exists
    existing = await db.admins.find_one({"username": admin_data.username})
    if existing:
        raise HTTPException(status_code=400, detail="Admin already exists")
    
    admin = Admin(
        username=admin_data.username,
        password_hash=hash_password(admin_data.password)
    )
    
    doc = admin.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.admins.insert_one(doc)
    
    return {"message": "Admin created successfully"}

@api_router.post("/admin/change-password")
@limiter.limit("3/minute")
async def change_password(
    request: Request,
    old_password: str = Form(...),
    new_password: str = Form(...),
    username: str = Depends(verify_token)
):
    # Validate new password
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not re.search(r'[a-z]', new_password):
        raise HTTPException(status_code=400, detail="Password must contain at least one lowercase letter")
    if not re.search(r'[A-Z]', new_password):
        raise HTTPException(status_code=400, detail="Password must contain at least one uppercase letter")
    if not re.search(r'\d', new_password):
        raise HTTPException(status_code=400, detail="Password must contain at least one digit")
    if not re.search(r'[@$!%*?&]', new_password):
        raise HTTPException(status_code=400, detail="Password must contain at least one special character (@$!%*?&)")
    
    admin = await db.admins.find_one({"username": username}, {"_id": 0})
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")
    
    if not verify_password(old_password, admin['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid old password")
    
    new_hash = hash_password(new_password)
    await db.admins.update_one(
        {"username": username},
        {"$set": {"password_hash": new_hash}}
    )
    
    return {"message": "Password changed successfully"}

# ============ ADMIN ROUTES (Protected) ============

@api_router.get("/admin/products", response_model=List[Product])
async def admin_get_products(username: str = Depends(verify_token)):
    products = await db.products.find({}, {"_id": 0}).to_list(1000)
    for product in products:
        if isinstance(product.get('created_at'), str):
            product['created_at'] = datetime.fromisoformat(product['created_at'])
        if isinstance(product.get('updated_at'), str):
            product['updated_at'] = datetime.fromisoformat(product['updated_at'])
    return products

@api_router.post("/admin/products", response_model=Product)
async def admin_create_product(product_data: ProductCreate, username: str = Depends(verify_token)):
    product = Product(**product_data.model_dump())
    doc = product.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['updated_at'] = doc['updated_at'].isoformat()
    await db.products.insert_one(doc)
    return product

@api_router.put("/admin/products/{product_id}", response_model=Product)
async def admin_update_product(product_id: str, product_data: ProductUpdate, username: str = Depends(verify_token)):
    update_data = {k: v for k, v in product_data.model_dump().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No data to update")
    
    update_data['updated_at'] = datetime.now(timezone.utc).isoformat()
    
    result = await db.products.update_one(
        {"id": product_id},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    
    product = await db.products.find_one({"id": product_id}, {"_id": 0})
    if isinstance(product.get('created_at'), str):
        product['created_at'] = datetime.fromisoformat(product['created_at'])
    if isinstance(product.get('updated_at'), str):
        product['updated_at'] = datetime.fromisoformat(product['updated_at'])
    return product

@api_router.delete("/admin/products/{product_id}")
async def admin_delete_product(product_id: str, username: str = Depends(verify_token)):
    result = await db.products.delete_one({"id": product_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"message": "Product deleted successfully"}

@api_router.get("/admin/orders", response_model=List[Order])
async def admin_get_orders(username: str = Depends(verify_token)):
    orders = await db.orders.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    for order in orders:
        if isinstance(order.get("created_at"), str):
            order["created_at"] = datetime.fromisoformat(order["created_at"])

        if isinstance(order.get("updated_at"), str):
            order["updated_at"] = datetime.fromisoformat(order["updated_at"])

        # 🔥 FIX FOR SHIPROCKET NUMERIC IDS
        if order.get("tracking_id") is not None:
            order["tracking_id"] = str(order["tracking_id"])

        if order.get("shiprocket_order_id") is not None:
            order["shiprocket_order_id"] = str(order["shiprocket_order_id"])
    return orders

@api_router.put("/admin/orders/{order_id}")
async def admin_update_order(order_id: str, status_data: OrderStatusUpdate, username: str = Depends(verify_token)):
    update_data = {
        "order_status": status_data.order_status,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    if status_data.tracking_id:
        update_data["tracking_id"] = status_data.tracking_id
    
    result = await db.orders.update_one(
        {"id": order_id},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Order not found")
    
    return {"message": "Order updated successfully"}

@api_router.get("/admin/stats")
async def admin_get_stats(username: str = Depends(verify_token)):
    total_products = await db.products.count_documents({})
    total_orders = await db.orders.count_documents({})
    pending_orders = await db.orders.count_documents({"order_status": "pending"})
    confirmed_orders = await db.orders.count_documents({"order_status": "confirmed"})
    
    # Calculate total revenue from paid orders
    pipeline = [
        {"$match": {"payment_status": "paid"}},
        {"$group": {"_id": None, "total_revenue": {"$sum": "$total"}}}
    ]
    revenue_result = await db.orders.aggregate(pipeline).to_list(1)
    total_revenue = revenue_result[0]['total_revenue'] if revenue_result else 0
    
    return {
        "total_products": total_products,
        "total_orders": total_orders,
        "pending_orders": pending_orders,
        "confirmed_orders": confirmed_orders,
        "total_revenue": total_revenue
    }

@api_router.post("/admin/shiprocket/create-order")
async def create_shiprocket_order(order_id: str, username: str = Depends(verify_token)):
    if not SHIPROCKET_EMAIL or not SHIPROCKET_PASSWORD:
        raise HTTPException(status_code=400, detail="Shiprocket not configured")
    
    # Get order details
    order = await db.orders.find_one({"id": order_id}, {"_id": 0})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    try:
        result = await create_shiprocket_shipment_internal(order)
        return {"message": "Shiprocket order created", "data": result}
    except Exception as e:
        logging.error(f"Shiprocket error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def create_shiprocket_shipment_internal(order: dict):
    try:
        # 1️⃣ Authenticate
        auth_response = requests.post(
            "https://apiv2.shiprocket.in/v1/external/auth/login",
            json={
                "email": SHIPROCKET_EMAIL,
                "password": SHIPROCKET_PASSWORD
            },
            timeout=30
        )

        auth_data = auth_response.json()
        token = auth_data.get("token")

        if not token:
            raise Exception(f"Shiprocket auth failed: {auth_data}")

        # 2️⃣ Prepare shipment payload (Shiprocket strict format)
        # Split name safely
        full_name = order["customer_name"].strip()
        name_parts = full_name.split(" ", 1)

        first_name = name_parts[0]
        last_name = name_parts[1] if len(name_parts) > 1 else "Customer"

        shipment_data = {
            "order_id": order["order_number"],
            "order_date": order["created_at"][:10],
            "pickup_location": "Primary",

            "billing_customer_name": full_name,
            "billing_first_name": first_name,
            "billing_last_name": last_name,

            "billing_address": order["shipping_address"],
            "billing_city": order["shipping_city"],
            "billing_pincode": str(order["shipping_pincode"]),
            "billing_state": order["shipping_state"],
            "billing_country": "India",
            "billing_email": order["customer_email"],
            "billing_phone": str(order["customer_phone"]),

            "shipping_is_billing": True,
            "order_items": [
                {
                    "name": item["product_name"],
                    "sku": str(item["product_id"]),
                    "units": int(item["quantity"]),
                    "selling_price": float(item["price"])
                }
                for item in order["items"]
            ],
            "payment_method": "Prepaid",
            "sub_total": float(order["subtotal"]),
            "length": 10,
            "breadth": 10,
            "height": 10,
            "weight": 0.5
        }


        # 3️⃣ Create shipment
        shipment_response = requests.post(
            "https://apiv2.shiprocket.in/v1/external/orders/create/adhoc",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },
            json=shipment_data,
            timeout=30
        )

        shipment_result = shipment_response.json()

        if shipment_response.status_code != 200:
            raise Exception(shipment_result)

        # 4️⃣ Save Shiprocket IDs
        await db.orders.update_one(
            {"id": order["id"]},
            {
                "$set": {
                    "shiprocket_order_id": str(shipment_result.get("order_id")),
                    "tracking_id": str(shipment_result.get("shipment_id")),
                    "updated_at": datetime.now(timezone.utc).isoformat()
                }
            }
        )

        return shipment_result

    except Exception as e:
        logging.error(f"Shiprocket error: {e}")
        raise


@api_router.post("/webhooks/shiprocket")
async def shiprocket_webhook(request: Request):
    """Webhook endpoint for Shiprocket tracking updates"""
    try:
        payload = await request.json()
        
        # Extract tracking info
        order_id = payload.get('order_id')
        shipment_status = payload.get('current_status')
        tracking_url = payload.get('track_url')
        
        if order_id:
            # Update order with tracking info
            update_data = {
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Map Shiprocket status to our order status
            status_mapping = {
                'SHIPPED': 'shipped',
                'IN TRANSIT': 'shipped',
                'OUT FOR DELIVERY': 'shipped',
                'DELIVERED': 'delivered',
                'RTO': 'cancelled',
                'LOST': 'cancelled'
            }
            
            if shipment_status in status_mapping:
                update_data['order_status'] = status_mapping[shipment_status]
            
            await db.orders.update_one(
                {"shiprocket_order_id": str(order_id)},
                {"$set": update_data}
            )
            
            logging.info(f"Webhook processed for order {order_id}: {shipment_status}")
        
        return {"status": "success"}
    except Exception as e:
        logging.error(f"Webhook error: {e}")
        return {"status": "error", "message": str(e)}

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://zenvy.biz",
        "https://www.zenvy.biz",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()