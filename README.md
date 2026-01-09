# Everything Store - E-Commerce Platform

A modern, conversion-focused e-commerce platform with guest checkout, order tracking, and comprehensive admin dashboard.

## Features

### Customer Features
- **Product Browsing**: Browse all products with search and price filtering
- **Product Details**: View detailed product information with image gallery
- **Guest Checkout**: No login required - quick and easy checkout process
- **Online Payment**: Secure payment via Razorpay integration
- **Order Tracking**: Track orders using unique order number
- **Responsive Design**: Neo-brutalist design optimized for all devices

### Admin Features
- **Dashboard**: View sales statistics and quick actions
- **Product Management**: Add, edit, and delete products with multiple images
- **Order Management**: View all orders, update status, add tracking IDs
- **Authentication**: Secure admin login with JWT

## Tech Stack

- **Frontend**: React, TailwindCSS, Lucide Icons
- **Backend**: FastAPI (Python), Motor (async MongoDB)
- **Database**: MongoDB
- **Payment**: Razorpay
- **Shipping**: Shiprocket (API ready)

## Setup Instructions

### Prerequisites
- Python 3.10+
- Node.js 18+
- MongoDB instance
- Razorpay account (for payments)
- Shiprocket account (for shipping, optional)

### Backend Setup

1. Navigate to backend directory:
```bash
cd backend
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables in `.env`:
```env
MONGO_URL=mongodb://localhost:27017
DB_NAME=ecommerce_db
CORS_ORIGINS=*
JWT_SECRET_KEY=your-super-secret-jwt-key-change-this

# Add these keys when ready
RAZORPAY_KEY_ID=your_razorpay_key_id
RAZORPAY_KEY_SECRET=your_razorpay_key_secret
SHIPROCKET_EMAIL=your_shiprocket_email
SHIPROCKET_PASSWORD=your_shiprocket_password
```

4. Create default admin user:
```bash
python -c "
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import bcrypt
import uuid
from datetime import datetime, timezone

async def create_admin():
    client = AsyncIOMotorClient('mongodb://localhost:27017')
    db = client['ecommerce_db']
    
    password_hash = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    admin = {
        'id': str(uuid.uuid4()),
        'username': 'admin',
        'password_hash': password_hash,
        'created_at': datetime.now(timezone.utc).isoformat()
    }
    
    await db.admins.insert_one(admin)
    print('Admin user created!')
    print('Username: admin')
    print('Password: admin123')
    client.close()

asyncio.run(create_admin())
"
```

5. The backend service will auto-start via supervisor

### Frontend Setup

1. Navigate to frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
yarn install
```

3. The frontend .env is already configured. To add Razorpay key for frontend:
```env
REACT_APP_RAZORPAY_KEY_ID=your_razorpay_key_id
```

4. The frontend service will auto-start via supervisor

### Restart Services (if needed)

```bash
sudo supervisorctl restart backend frontend
```

## API Keys Setup

### Where to Add API Keys

1. **Razorpay Keys**:
   - Sign up at https://razorpay.com/
   - Go to Settings → API Keys
   - Generate Test/Live keys
   - Add to `/app/backend/.env`:
     ```
     RAZORPAY_KEY_ID=rzp_test_xxxxxxxxxxxxx
     RAZORPAY_KEY_SECRET=xxxxxxxxxxxxxxxxxxxxx
     ```
   - Add to `/app/frontend/.env`:
     ```
     REACT_APP_RAZORPAY_KEY_ID=rzp_test_xxxxxxxxxxxxx
     ```

2. **Shiprocket Keys**:
   - Sign up at https://shiprocket.in/
   - Go to Settings → API
   - Create API user
   - Add to `/app/backend/.env`:
     ```
     SHIPROCKET_EMAIL=your_api_user@email.com
     SHIPROCKET_PASSWORD=your_api_password
     ```

### After Adding Keys

1. Restart backend service:
```bash
sudo supervisorctl restart backend
```

2. Restart frontend service (if Razorpay key added):
```bash
sudo supervisorctl restart frontend
```

## Usage

### Admin Access
1. Go to `/admin`
2. Default credentials:
   - Username: `admin`
   - Password: `admin123`
3. Change password immediately after first login!

### Adding Products
1. Login to admin dashboard
2. Go to "Manage Products"
3. Click "Add Product"
4. Fill in product details
5. Add image URLs (one per line)
6. Set price, discount, and stock
7. Click "Create"

### Managing Orders
1. Login to admin dashboard
2. Go to "Manage Orders"
3. View all orders with customer details
4. Click "Update Status" to change order status
5. Add tracking ID when shipped

### Customer Flow
1. Browse products on home page or `/products`
2. Search or filter by price
3. Click product to view details
4. Add to cart
5. Proceed to checkout (no login required)
6. Fill in shipping details
7. Complete payment via Razorpay
8. Receive order confirmation with order number
9. Track order status at `/track-order`

## Design System

The app uses a Neo-Brutalist design system with:
- **Fonts**: Syne (headings), Manrope (body)
- **Colors**: 
  - Primary: Electric Blue (#0047FF)
  - Secondary: Neon Lime (#CCFF00)
  - Accent: Orange Red (#FF4D00)
- **Shadows**: Hard shadows (4px 4px 0px 0px rgba(0,0,0,1))
- **Borders**: 2px solid black
- **Corners**: Sharp edges (rounded-none)

## API Endpoints

### Public Endpoints
- `GET /api/products` - List all products
- `GET /api/products/{id}` - Get product details
- `POST /api/orders` - Create new order
- `POST /api/orders/verify-payment` - Verify Razorpay payment
- `GET /api/orders/track/{order_number}` - Track order

### Admin Endpoints (Requires JWT)
- `POST /api/admin/login` - Admin login
- `GET /api/admin/products` - List all products
- `POST /api/admin/products` - Create product
- `PUT /api/admin/products/{id}` - Update product
- `DELETE /api/admin/products/{id}` - Delete product
- `GET /api/admin/orders` - List all orders
- `PUT /api/admin/orders/{id}` - Update order status
- `GET /api/admin/stats` - Get dashboard statistics

## Testing

### Test Payment
Razorpay provides test cards:
- Card Number: `4111 1111 1111 1111`
- CVV: Any 3 digits
- Expiry: Any future date

### Test Order Flow
1. Add products from admin panel
2. Browse as customer
3. Add to cart and checkout
4. Use test payment details
5. Track order with order number

## Production Deployment

1. Update `.env` files with production values
2. Set strong JWT secret
3. Use production Razorpay keys
4. Configure production MongoDB
5. Set up SSL/HTTPS
6. Update CORS origins
7. Enable rate limiting
8. Set up monitoring and logging

## Support

For issues or questions:
- Check backend logs: `tail -f /var/log/supervisor/backend.err.log`
- Check frontend logs: `tail -f /var/log/supervisor/frontend.err.log`
- Restart services: `sudo supervisorctl restart backend frontend`

## License

MIT License - Feel free to use for personal and commercial projects.
