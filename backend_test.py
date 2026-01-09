import requests
import sys
import json
from datetime import datetime

class ECommerceAPITester:
    def __init__(self, base_url="https://webstore-tracker.preview.emergentagent.com/api"):
        self.base_url = base_url
        self.token = None
        self.tests_run = 0
        self.tests_passed = 0
        self.created_product_id = None
        self.created_order_id = None

    def run_test(self, name, method, endpoint, expected_status, data=None, headers=None):
        """Run a single API test"""
        url = f"{self.base_url}/{endpoint}" if not endpoint.startswith('http') else endpoint
        test_headers = {'Content-Type': 'application/json'}
        
        if self.token:
            test_headers['Authorization'] = f'Bearer {self.token}'
        if headers:
            test_headers.update(headers)

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=test_headers, timeout=10)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=test_headers, timeout=10)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=test_headers, timeout=10)
            elif method == 'DELETE':
                response = requests.delete(url, headers=test_headers, timeout=10)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ PASSED - Status: {response.status_code}")
                try:
                    return True, response.json()
                except:
                    return True, {}
            else:
                print(f"❌ FAILED - Expected {expected_status}, got {response.status_code}")
                try:
                    error_detail = response.json()
                    print(f"   Error: {error_detail}")
                except:
                    print(f"   Response: {response.text}")
                return False, {}

        except Exception as e:
            print(f"❌ FAILED - Error: {str(e)}")
            return False, {}

    def test_root_endpoint(self):
        """Test root API endpoint"""
        return self.run_test("Root Endpoint", "GET", "", 200)

    def test_get_products(self):
        """Test getting all products"""
        success, response = self.run_test("Get All Products", "GET", "products", 200)
        if success and isinstance(response, list):
            print(f"   Found {len(response)} products")
            if len(response) >= 8:
                print("   ✅ Expected 8+ sample products found")
            else:
                print(f"   ⚠️  Only {len(response)} products found, expected 8+")
        return success, response

    def test_search_products(self):
        """Test product search functionality"""
        return self.run_test("Search Products (headphones)", "GET", "products?search=headphones", 200)

    def test_filter_products(self):
        """Test product price filtering"""
        return self.run_test("Filter Products (1000-3000)", "GET", "products?min_price=1000&max_price=3000", 200)

    def test_get_single_product(self, product_id):
        """Test getting a single product"""
        return self.run_test("Get Single Product", "GET", f"products/{product_id}", 200)

    def test_admin_login(self):
        """Test admin login"""
        success, response = self.run_test(
            "Admin Login",
            "POST",
            "admin/login",
            200,
            data={"username": "admin", "password": "admin123"}
        )
        if success and 'access_token' in response:
            self.token = response['access_token']
            print("   ✅ Admin token obtained")
            return True
        return False

    def test_admin_stats(self):
        """Test admin dashboard stats"""
        return self.run_test("Admin Stats", "GET", "admin/stats", 200)

    def test_admin_get_products(self):
        """Test admin get products"""
        return self.run_test("Admin Get Products", "GET", "admin/products", 200)

    def test_admin_create_product(self):
        """Test admin create product"""
        product_data = {
            "name": "Test Product API",
            "description": "This is a test product created via API",
            "price": 1500.0,
            "discount": 10.0,
            "stock": 20,
            "images": ["https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=800"]
        }
        success, response = self.run_test("Admin Create Product", "POST", "admin/products", 200, data=product_data)
        if success and 'id' in response:
            self.created_product_id = response['id']
            print(f"   ✅ Product created with ID: {self.created_product_id}")
        return success, response

    def test_admin_update_product(self):
        """Test admin update product"""
        if not self.created_product_id:
            print("   ⚠️  No product ID available for update test")
            return False, {}
        
        update_data = {"stock": 100}
        return self.run_test("Admin Update Product", "PUT", f"admin/products/{self.created_product_id}", 200, data=update_data)

    def test_admin_get_orders(self):
        """Test admin get orders"""
        return self.run_test("Admin Get Orders", "GET", "admin/orders", 200)

    def test_create_order(self):
        """Test creating an order"""
        order_data = {
            "customer_name": "Test Customer",
            "customer_email": "test@example.com",
            "customer_phone": "9876543210",
            "shipping_address": "123 Test Street",
            "shipping_city": "Mumbai",
            "shipping_state": "Maharashtra",
            "shipping_pincode": "400001",
            "items": [
                {
                    "product_id": "test-product-1",
                    "product_name": "Test Product",
                    "price": 1500.0,
                    "quantity": 1,
                    "image": "https://example.com/image.jpg"
                }
            ],
            "subtotal": 1500.0,
            "total": 1500.0
        }
        success, response = self.run_test("Create Order", "POST", "orders", 200, data=order_data)
        if success and 'order_number' in response:
            self.created_order_id = response['order_number']
            print(f"   ✅ Order created with number: {self.created_order_id}")
        return success, response

    def test_track_order_valid(self):
        """Test tracking a valid order"""
        if not self.created_order_id:
            print("   ⚠️  No order ID available for tracking test")
            return False, {}
        return self.run_test("Track Valid Order", "GET", f"orders/track/{self.created_order_id}", 200)

    def test_track_order_invalid(self):
        """Test tracking an invalid order"""
        return self.run_test("Track Invalid Order", "GET", "orders/track/INVALID123", 404)

    def test_razorpay_not_configured(self):
        """Test that Razorpay shows proper error when not configured"""
        payment_data = {
            "razorpay_order_id": "test_order_id",
            "razorpay_payment_id": "test_payment_id",
            "razorpay_signature": "test_signature"
        }
        success, response = self.run_test("Razorpay Not Configured", "POST", "orders/verify-payment", 400, data=payment_data)
        if not success:
            print("   ✅ Expected failure - Razorpay not configured")
            return True
        return False

def main():
    print("🚀 Starting E-Commerce API Tests")
    print("=" * 50)
    
    tester = ECommerceAPITester()
    
    # Test public endpoints first
    print("\n📋 TESTING PUBLIC ENDPOINTS")
    print("-" * 30)
    
    tester.test_root_endpoint()
    
    # Test product endpoints
    success, products = tester.test_get_products()
    if success and products:
        # Test with first product if available
        if len(products) > 0:
            first_product_id = products[0].get('id')
            if first_product_id:
                tester.test_get_single_product(first_product_id)
    
    tester.test_search_products()
    tester.test_filter_products()
    
    # Test order creation
    tester.test_create_order()
    tester.test_track_order_valid()
    tester.test_track_order_invalid()
    
    # Test Razorpay error handling
    tester.test_razorpay_not_configured()
    
    # Test admin endpoints
    print("\n🔐 TESTING ADMIN ENDPOINTS")
    print("-" * 30)
    
    if tester.test_admin_login():
        tester.test_admin_stats()
        tester.test_admin_get_products()
        tester.test_admin_get_orders()
        tester.test_admin_create_product()
        tester.test_admin_update_product()
    else:
        print("❌ Admin login failed, skipping admin tests")
    
    # Print final results
    print("\n" + "=" * 50)
    print(f"📊 FINAL RESULTS: {tester.tests_passed}/{tester.tests_run} tests passed")
    
    if tester.tests_passed == tester.tests_run:
        print("🎉 ALL TESTS PASSED!")
        return 0
    else:
        failed = tester.tests_run - tester.tests_passed
        print(f"⚠️  {failed} tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())