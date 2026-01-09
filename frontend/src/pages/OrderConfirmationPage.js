import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { CheckCircle, Package } from 'lucide-react';
import api from '../utils/api';

export const OrderConfirmationPage = () => {
  const { orderNumber } = useParams();
  const [order, setOrder] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchOrder = async () => {
      try {
        const response = await api.get(`/orders/track/${orderNumber}`);
        setOrder(response.data);
      } catch (error) {
        console.error('Failed to fetch order:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchOrder();
  }, [orderNumber]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center" data-testid="loading-confirmation">
        <div className="animate-pulse text-gray-500 font-manrope">Loading order details...</div>
      </div>
    );
  }

  if (!order) {
    return (
      <div className="min-h-screen flex items-center justify-center" data-testid="order-not-found">
        <div className="text-center">
          <p className="text-xl font-manrope text-gray-600 mb-4">Order not found</p>
          <Link
            to="/products"
            className="inline-block bg-brutalist-primary text-white font-bold py-3 px-6 border-2 border-black shadow-brutalist hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-none transition-all"
          >
            CONTINUE SHOPPING
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50" data-testid="order-confirmation-page">
      <div className="max-w-[800px] mx-auto p-4 md:p-8">
        {/* Success Message */}
        <div className="bg-white border-2 border-black p-8 text-center mb-8" data-testid="success-message">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-brutalist-secondary border-2 border-black mb-4">
            <CheckCircle className="w-12 h-12" />
          </div>
          <h1 className="text-4xl md:text-5xl font-syne font-bold tracking-tight mb-4">
            ORDER CONFIRMED!
          </h1>
          <p className="text-lg font-manrope text-gray-600 mb-6">
            Thank you for your order. We'll send you a confirmation email shortly.
          </p>
          <div className="bg-gray-50 border-2 border-black p-6">
            <p className="text-sm font-mono uppercase mb-2 text-gray-600">Your Order Number</p>
            <p className="text-3xl font-bold font-mono" data-testid="order-number-display">{order.order_number}</p>
          </div>
        </div>

        {/* Order Details */}
        <div className="bg-white border-2 border-black p-6 mb-6" data-testid="order-details">
          <h2 className="font-syne font-bold text-2xl mb-4">ORDER DETAILS</h2>
          <div className="space-y-3">
            <div className="flex justify-between py-2 border-b border-gray-200">
              <span className="font-manrope">Order Date</span>
              <span className="font-bold" data-testid="order-date">
                {new Date(order.created_at).toLocaleDateString()}
              </span>
            </div>
            <div className="flex justify-between py-2 border-b border-gray-200">
              <span className="font-manrope">Total Amount</span>
              <span className="font-bold font-mono text-xl" data-testid="order-total">
                ₹{order.total.toFixed(2)}
              </span>
            </div>
            <div className="flex justify-between py-2 border-b border-gray-200">
              <span className="font-manrope">Payment Status</span>
              <span className="font-bold uppercase" data-testid="payment-status">
                {order.payment_status}
              </span>
            </div>
            <div className="flex justify-between py-2">
              <span className="font-manrope">Order Status</span>
              <span className="font-bold uppercase" data-testid="order-status">
                {order.order_status}
              </span>
            </div>
          </div>
        </div>

        {/* Items */}
        <div className="bg-white border-2 border-black p-6 mb-6" data-testid="order-items">
          <h2 className="font-syne font-bold text-2xl mb-4">ITEMS</h2>
          <div className="space-y-4">
            {order.items.map((item, index) => (
              <div key={index} className="flex gap-4 pb-4 border-b border-gray-200 last:border-0" data-testid={`order-item-${index}`}>
                <img
                  src={item.image}
                  alt={item.product_name}
                  className="w-20 h-20 object-cover border-2 border-black"
                />
                <div className="flex-1">
                  <h3 className="font-bold font-manrope mb-1">{item.product_name}</h3>
                  <p className="text-sm text-gray-600">Quantity: {item.quantity}</p>
                  <p className="font-bold font-mono">₹{item.price.toFixed(2)} each</p>
                </div>
                <div className="text-right">
                  <p className="font-bold font-mono text-lg">
                    ₹{(item.price * item.quantity).toFixed(2)}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Shipping Address */}
        <div className="bg-white border-2 border-black p-6 mb-8" data-testid="shipping-address">
          <h2 className="font-syne font-bold text-2xl mb-4">SHIPPING ADDRESS</h2>
          <div className="font-manrope">
            <p className="font-bold">{order.customer_name}</p>
            <p>{order.shipping_address}</p>
            <p>{order.shipping_city}, {order.shipping_state}</p>
            <p>{order.shipping_pincode}</p>
            <p className="mt-2">{order.customer_phone}</p>
            <p>{order.customer_email}</p>
          </div>
        </div>

        {/* Actions */}
        <div className="flex flex-col sm:flex-row gap-4">
          <Link
            to="/products"
            className="flex-1 text-center bg-black text-white font-bold py-4 px-8 border-2 border-black shadow-brutalist hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-none transition-all"
            data-testid="continue-shopping-btn"
          >
            CONTINUE SHOPPING
          </Link>
          <Link
            to="/track-order"
            className="flex-1 text-center bg-brutalist-secondary text-black font-bold py-4 px-8 border-2 border-black shadow-brutalist hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-none transition-all flex items-center justify-center gap-2"
            data-testid="track-order-btn"
          >
            <Package className="w-5 h-5" />
            TRACK ORDER
          </Link>
        </div>
      </div>
    </div>
  );
};