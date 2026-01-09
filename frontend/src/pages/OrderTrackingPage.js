import React, { useState } from 'react';
import { Search, Package, Truck, CheckCircle } from 'lucide-react';
import api from '../utils/api';
import { toast } from 'sonner';

export const OrderTrackingPage = () => {
  const [orderNumber, setOrderNumber] = useState('');
  const [order, setOrder] = useState(null);
  const [loading, setLoading] = useState(false);
  const [notFound, setNotFound] = useState(false);

  const handleTrack = async (e) => {
    e.preventDefault();
    if (!orderNumber.trim()) {
      toast.error('Please enter an order number');
      return;
    }

    setLoading(true);
    setNotFound(false);
    setOrder(null);

    try {
      const response = await api.get(`/orders/track/${orderNumber.trim().toUpperCase()}`);
      setOrder(response.data);
    } catch (error) {
      console.error('Order not found:', error);
      setNotFound(true);
      toast.error('Order not found');
    } finally {
      setLoading(false);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'pending':
        return <Package className="w-6 h-6" />;
      case 'confirmed':
      case 'packed':
        return <Package className="w-6 h-6" />;
      case 'shipped':
        return <Truck className="w-6 h-6" />;
      case 'delivered':
        return <CheckCircle className="w-6 h-6" />;
      default:
        return <Package className="w-6 h-6" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'pending':
        return 'bg-gray-100 text-gray-800 border-gray-300';
      case 'confirmed':
        return 'bg-blue-100 text-blue-800 border-blue-300';
      case 'packed':
        return 'bg-purple-100 text-purple-800 border-purple-300';
      case 'shipped':
        return 'bg-yellow-100 text-yellow-800 border-yellow-300';
      case 'delivered':
        return 'bg-green-100 text-green-800 border-green-300';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-300';
    }
  };

  const statusTimeline = ['pending', 'confirmed', 'packed', 'shipped', 'delivered'];
  const currentStatusIndex = order ? statusTimeline.indexOf(order.order_status) : -1;

  return (
    <div className="min-h-screen bg-gray-50" data-testid="order-tracking-page">
      <div className="max-w-[800px] mx-auto p-4 md:p-8">
        <div className="bg-white border-2 border-black p-8">
          <h1 className="text-4xl md:text-5xl font-syne font-bold tracking-tight mb-4" data-testid="tracking-title">
            TRACK YOUR ORDER
          </h1>
          <p className="font-manrope text-gray-600 mb-6">
            Enter your order number to check the status of your delivery.
          </p>

          {/* Search Form */}
          <form onSubmit={handleTrack} className="mb-8" data-testid="tracking-form">
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Enter Order Number (e.g., ORD-12345678)"
                value={orderNumber}
                onChange={(e) => setOrderNumber(e.target.value)}
                className="flex-1 border-2 border-black p-4 text-lg focus:outline-none focus:shadow-brutalist transition-all font-mono uppercase"
                data-testid="order-number-input"
              />
              <button
                type="submit"
                disabled={loading}
                className="bg-brutalist-primary text-white font-bold px-8 border-2 border-black shadow-brutalist hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-none transition-all disabled:opacity-50"
                data-testid="track-btn"
              >
                <Search className="w-6 h-6" />
              </button>
            </div>
          </form>

          {/* Loading State */}
          {loading && (
            <div className="text-center py-8" data-testid="tracking-loading">
              <div className="animate-pulse text-gray-500 font-manrope">Searching for your order...</div>
            </div>
          )}

          {/* Not Found */}
          {notFound && (
            <div className="border-2 border-red-300 bg-red-50 p-6 text-center" data-testid="order-not-found-message">
              <p className="text-red-800 font-bold mb-2">Order Not Found</p>
              <p className="text-red-600 text-sm">Please check your order number and try again.</p>
            </div>
          )}

          {/* Order Found */}
          {order && (
            <div className="space-y-6" data-testid="order-tracking-details">
              {/* Order Info */}
              <div className="border-2 border-black p-6 bg-gray-50">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <p className="text-sm font-mono uppercase text-gray-600">Order Number</p>
                    <p className="text-2xl font-bold font-mono" data-testid="tracked-order-number">{order.order_number}</p>
                  </div>
                  <div className={`px-4 py-2 border-2 font-bold uppercase ${getStatusColor(order.order_status)}`} data-testid="tracked-order-status">
                    {order.order_status}
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-gray-600">Order Date</p>
                    <p className="font-bold" data-testid="tracked-order-date">
                      {new Date(order.created_at).toLocaleDateString()}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-600">Total Amount</p>
                    <p className="font-bold font-mono" data-testid="tracked-order-amount">₹{order.total.toFixed(2)}</p>
                  </div>
                </div>
                {order.tracking_id && (
                  <div className="mt-4 pt-4 border-t border-gray-300">
                    <p className="text-gray-600 text-sm">Tracking ID</p>
                    <p className="font-bold font-mono" data-testid="tracking-id">{order.tracking_id}</p>
                  </div>
                )}
              </div>

              {/* Timeline */}
              <div className="border-2 border-black p-6">
                <h3 className="font-syne font-bold text-xl mb-6">ORDER TIMELINE</h3>
                <div className="space-y-4">
                  {statusTimeline.map((status, index) => {
                    const isCompleted = index <= currentStatusIndex;
                    const isCurrent = index === currentStatusIndex;
                    return (
                      <div key={status} className="flex items-start gap-4" data-testid={`timeline-${status}`}>
                        <div className={`flex items-center justify-center w-12 h-12 border-2 border-black ${
                          isCompleted ? 'bg-brutalist-primary text-white' : 'bg-gray-100'
                        }`}>
                          {getStatusIcon(status)}
                        </div>
                        <div className="flex-1">
                          <p className={`font-bold uppercase ${
                            isCurrent ? 'text-brutalist-primary' : isCompleted ? 'text-black' : 'text-gray-400'
                          }`}>
                            {status}
                          </p>
                          {isCurrent && (
                            <p className="text-sm text-gray-600 mt-1">
                              Updated {new Date(order.updated_at).toLocaleString()}
                            </p>
                          )}
                        </div>
                        {isCompleted && (
                          <CheckCircle className="w-5 h-5 text-green-600" />
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Shipping Address */}
              <div className="border-2 border-black p-6">
                <h3 className="font-syne font-bold text-xl mb-4">DELIVERY ADDRESS</h3>
                <div className="font-manrope" data-testid="delivery-address">
                  <p className="font-bold">{order.customer_name}</p>
                  <p>{order.shipping_address}</p>
                  <p>{order.shipping_city}, {order.shipping_state}</p>
                  <p>{order.shipping_pincode}</p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};