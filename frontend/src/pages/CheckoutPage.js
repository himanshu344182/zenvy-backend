import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getCart, getCartTotal, clearCart } from '../utils/cart';
import api from '../utils/api';
import { toast } from 'sonner';
// import { useRazorpay } from 'react-razorpay';

export const CheckoutPage = () => {
  const navigate = useNavigate();
  // const Razorpay = useRazorpay();
  const [cart, setCart] = useState([]);
  const [loading, setLoading] = useState(false);
  
  const [formData, setFormData] = useState({
    customer_name: '',
    customer_email: '',
    customer_phone: '',
    shipping_address: '',
    shipping_city: '',
    shipping_state: '',
    shipping_pincode: ''
  });

  useEffect(() => {
    const cartItems = getCart();
    if (cartItems.length === 0) {
      toast.error('Your cart is empty');
      navigate('/products');
    }
    setCart(cartItems);
  }, [navigate]);

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    console.log(
      "Razorpay key from env:",
      process.env.REACT_APP_RAZORPAY_KEY_ID
      );

    setLoading(true);

    try {
      const subtotal = getCartTotal();
      const orderData = {
        ...formData,
        items: cart.map(item => ({
          product_id: item.product_id || item.id,
          product_name: item.product_name || item.name,
          price: Number(item.price),
          quantity: Number(item.quantity),
          image: item.image || item.images?.[0]
        })),
        subtotal: Number(subtotal),
        total: Number(subtotal)
      };


      // Create order
      const response = await api.post('/orders', orderData);
      const order = response.data;

      // Check if Razorpay is configured
      // if (!order.razorpay_order_id) {
      //   toast.error('Payment gateway not configured. Please contact admin.');
      //   setLoading(false);
      //   return;
      // }
      if (!order.razorpay_order_id) {
         toast.success('Order placed successfully');
         clearCart();
         navigate(`/order-confirmation/${order.order_number}`);
         return;
          }


      // Initialize Razorpay payment
      const options = {
        key: process.env.REACT_APP_RAZORPAY_KEY_ID || '',
        amount: order.total * 100,
        currency: 'INR',
        name: 'Everything Store',
        description: `Order ${order.order_number}`,
        order_id: order.razorpay_order_id,
        handler: async (response) => {
          try {
            // Verify payment
            await api.post('/orders/verify-payment', {
              razorpay_order_id: response.razorpay_order_id,
              razorpay_payment_id: response.razorpay_payment_id,
              razorpay_signature: response.razorpay_signature
            });

            clearCart();
            toast.success('Payment successful!');
            navigate(`/order-confirmation/${order.order_number}`);
          } catch (error) {
            console.error('Payment verification failed:', error);
            toast.error('Payment verification failed');
          }
        },
        prefill: {
          name: formData.customer_name,
          email: formData.customer_email,
          contact: formData.customer_phone
        },
        theme: {
          color: '#0047FF'
        },
        modal: {
          ondismiss: () => {
            setLoading(false);
            toast.info('Payment cancelled');
          }
        }
      };

      // const razorpayInstance = new Razorpay(options);
      const razorpayInstance = new window.Razorpay(options);
      razorpayInstance.open();
    } catch (error) {
      console.error('Order creation failed:', error);
      toast.error('Failed to create order');
      setLoading(false);
    }
  };

  const subtotal = getCartTotal();

  return (
    <div className="min-h-screen bg-gray-50" data-testid="checkout-page">
      <div className="max-w-[1200px] mx-auto p-4 md:p-8">
        <h1 className="text-4xl md:text-5xl font-display font-bold mb-2 bg-gradient-to-r from-zenvy-primary to-zenvy-secondary bg-clip-text text-transparent" data-testid="checkout-title">
          Checkout
        </h1>
        <p className="text-gray-600 mb-8">Complete your order securely</p>

        <div className="grid md:grid-cols-3 gap-8">
          {/* Form */}
          <form onSubmit={handleSubmit} className="md:col-span-2 space-y-6" data-testid="checkout-form">
            {/* Customer Details */}
            <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-soft">
              <h2 className="font-display font-bold text-xl mb-6 text-gray-900">Customer Details</h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">Full Name *</label>
                  <input
                    type="text"
                    name="customer_name"
                    value={formData.customer_name}
                    onChange={handleInputChange}
                    required
                    className="w-full border-2 border-gray-300 rounded-xl p-3 focus:outline-none focus:ring-2 focus:ring-zenvy-primary focus:border-transparent transition-all"
                    data-testid="customer-name-input"
                    placeholder="Enter your full name"
                  />
                </div>
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">Email *</label>
                  <input
                    type="email"
                    name="customer_email"
                    value={formData.customer_email}
                    onChange={handleInputChange}
                    required
                    className="w-full border-2 border-gray-300 rounded-xl p-3 focus:outline-none focus:ring-2 focus:ring-zenvy-primary focus:border-transparent transition-all"
                    data-testid="customer-email-input"
                    placeholder="your@email.com"
                  />
                </div>
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">Phone *</label>
                  <input
                    type="tel"
                    name="customer_phone"
                    value={formData.customer_phone}
                    onChange={handleInputChange}
                    required
                    pattern="[0-9]{10}"
                    className="w-full border-2 border-gray-300 rounded-xl p-3 focus:outline-none focus:ring-2 focus:ring-zenvy-primary focus:border-transparent transition-all"
                    data-testid="customer-phone-input"
                    placeholder="10-digit mobile number"
                  />
                </div>
              </div>
            </div>

            {/* Shipping Address */}
            <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-soft">
              <h2 className="font-display font-bold text-xl mb-6 text-gray-900">Shipping Address</h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">Address *</label>
                  <textarea
                    name="shipping_address"
                    value={formData.shipping_address}
                    onChange={handleInputChange}
                    required
                    rows="3"
                    className="w-full border-2 border-gray-300 rounded-xl p-3 focus:outline-none focus:ring-2 focus:ring-zenvy-primary focus:border-transparent transition-all"
                    data-testid="shipping-address-input"
                    placeholder="House no, Street, Landmark"
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">City *</label>
                    <input
                      type="text"
                      name="shipping_city"
                      value={formData.shipping_city}
                      onChange={handleInputChange}
                      required
                      className="w-full border-2 border-gray-300 rounded-xl p-3 focus:outline-none focus:ring-2 focus:ring-zenvy-primary focus:border-transparent transition-all"
                      data-testid="shipping-city-input"
                      placeholder="City"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">State *</label>
                    <input
                      type="text"
                      name="shipping_state"
                      value={formData.shipping_state}
                      onChange={handleInputChange}
                      required
                      className="w-full border-2 border-gray-300 rounded-xl p-3 focus:outline-none focus:ring-2 focus:ring-zenvy-primary focus:border-transparent transition-all"
                      data-testid="shipping-state-input"
                      placeholder="State"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">Pincode *</label>
                  <input
                    type="text"
                    name="shipping_pincode"
                    value={formData.shipping_pincode}
                    onChange={handleInputChange}
                    required
                    pattern="[0-9]{6}"
                    className="w-full border-2 border-gray-300 rounded-xl p-3 focus:outline-none focus:ring-2 focus:ring-zenvy-primary focus:border-transparent transition-all"
                    data-testid="shipping-pincode-input"
                    placeholder="6-digit pincode"
                  />
                </div>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-zenvy-primary to-zenvy-secondary text-white font-bold py-4 px-8 rounded-xl shadow-medium hover:shadow-large hover:scale-[1.02] transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100 text-lg"
              data-testid="place-order-btn"
            >
              {loading ? 'Processing...' : 'Proceed to Payment'}
            </button>
          </form>

          {/* Order Summary */}
          <div className="md:col-span-1">
            <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-soft sticky top-24" data-testid="order-summary">
              <h2 className="font-display font-bold text-xl mb-6 text-gray-900">Order Summary</h2>
              <div className="space-y-4 mb-6">
                {cart.map((item) => (
                  <div key={item.product_id} className="flex gap-3 pb-4 border-b border-gray-100 last:border-0" data-testid={`summary-item-${item.product_id}`}>
                    <img
                      src={item.image}
                      alt={item.product_name}
                      className="w-16 h-16 object-cover rounded-lg border border-gray-200"
                    />
                    <div className="flex-1">
                      <p className="font-semibold text-sm line-clamp-2 text-gray-900">{item.product_name}</p>
                      <p className="text-sm text-gray-600">Qty: {item.quantity}</p>
                      <p className="font-bold text-zenvy-primary">₹{(item.price * item.quantity).toFixed(2)}</p>
                    </div>
                  </div>
                ))}
              </div>
              <div className="space-y-3 mb-6 pt-4 border-t-2 border-gray-200">
                <div className="flex justify-between text-gray-600">
                  <span>Subtotal</span>
                  <span className="font-semibold" data-testid="summary-subtotal">₹{subtotal.toFixed(2)}</span>
                </div>
                <div className="flex justify-between text-gray-600">
                  <span>Shipping</span>
                  <span className="font-semibold text-green-600">FREE</span>
                </div>
                <div className="pt-3 border-t border-gray-200">
                  <div className="flex justify-between items-center">
                    <span className="font-display font-bold text-lg text-gray-900">Total</span>
                    <span className="font-bold text-2xl bg-gradient-to-r from-zenvy-primary to-zenvy-secondary bg-clip-text text-transparent" data-testid="summary-total">₹{subtotal.toFixed(2)}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};