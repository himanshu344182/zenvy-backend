import React, { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ArrowLeft, Package, Truck } from 'lucide-react';
import api from '../../utils/api';
import { toast } from 'sonner';

export const AdminOrdersPage = () => {
  const navigate = useNavigate();
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedOrder, setSelectedOrder] = useState(null);
  const [statusUpdate, setStatusUpdate] = useState({ order_status: '', tracking_id: '' });
  const [creatingLabel, setCreatingLabel] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem('admin_token');
    if (!token) {
      navigate('/admin');
      return;
    }
    fetchOrders();
  }, [navigate]);

  const fetchOrders = async () => {
    try {
      const response = await api.get('/admin/orders');
      setOrders(response.data);
    } catch (error) {
      console.error('Failed to fetch orders:', error);
      if (error.response?.status === 401) {
        toast.error('Session expired');
        localStorage.removeItem('admin_token');
        navigate('/admin');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateOrder = async (e) => {
    e.preventDefault();
    
    try {
      await api.put(`/admin/orders/${selectedOrder.id}`, statusUpdate);
      toast.success('Order updated successfully');
      setSelectedOrder(null);
      setStatusUpdate({ order_status: '', tracking_id: '' });
      fetchOrders();
    } catch (error) {
      console.error('Failed to update order:', error);
      toast.error('Failed to update order');
    }
  };

  const handleCreateShippingLabel = async (orderId) => {
    if (!window.confirm('Create shipping label via Shiprocket? Make sure Shiprocket is configured.')) {
      return;
    }

    setCreatingLabel(true);
    try {
      const response = await api.post(`/admin/shiprocket/create-order?order_id=${orderId}`);
      toast.success('Shipping label created successfully!');
      fetchOrders();
    } catch (error) {
      console.error('Failed to create shipping label:', error);
      toast.error(error.response?.data?.detail || 'Failed to create shipping label. Check if Shiprocket is configured.');
    } finally {
      setCreatingLabel(false);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'pending': return 'bg-gray-100 text-gray-800 border-gray-300';
      case 'confirmed': return 'bg-blue-100 text-blue-800 border-blue-300';
      case 'packed': return 'bg-purple-100 text-purple-800 border-purple-300';
      case 'shipped': return 'bg-yellow-100 text-yellow-800 border-yellow-300';
      case 'delivered': return 'bg-green-100 text-green-800 border-green-300';
      case 'cancelled': return 'bg-red-100 text-red-800 border-red-300';
      default: return 'bg-gray-100 text-gray-800 border-gray-300';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50" data-testid="admin-orders-page">
      {/* Header */}
      <div className="bg-white border-b-2 border-black">
        <div className="max-w-[1400px] mx-auto p-4 md:p-6">
          <div className="flex items-center gap-4">
            <Link to="/admin/dashboard" className="p-2 hover:bg-gray-100 transition-colors" data-testid="back-to-dashboard-btn">
              <ArrowLeft className="w-6 h-6" />
            </Link>
            <h1 className="text-3xl font-syne font-bold" data-testid="orders-title">ORDERS</h1>
          </div>
        </div>
      </div>

      <div className="max-w-[1400px] mx-auto p-4 md:p-8">
        {/* Update Form Modal */}
        {selectedOrder && (
          <div className="fixed inset-0 bg-black bg-opacity-50 z-40 flex items-center justify-center p-4" onClick={() => setSelectedOrder(null)} data-testid="order-update-modal">
            <div className="bg-white border-2 border-black p-6 max-w-md w-full" onClick={(e) => e.stopPropagation()}>
              <h2 className="font-syne font-bold text-2xl mb-4">UPDATE ORDER</h2>
              <p className="font-mono text-sm mb-4">Order: {selectedOrder.order_number}</p>
              <form onSubmit={handleUpdateOrder} className="space-y-4">
                <div>
                  <label className="block text-sm font-mono uppercase mb-2">Order Status *</label>
                  <select
                    value={statusUpdate.order_status}
                    onChange={(e) => setStatusUpdate({ ...statusUpdate, order_status: e.target.value })}
                    required
                    className="w-full border-2 border-black p-3 focus:outline-none focus:shadow-brutalist transition-all"
                    data-testid="order-status-select"
                  >
                    <option value="">Select Status</option>
                    <option value="pending">Pending</option>
                    <option value="confirmed">Confirmed</option>
                    <option value="packed">Packed</option>
                    <option value="shipped">Shipped</option>
                    <option value="delivered">Delivered</option>
                    <option value="cancelled">Cancelled</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-mono uppercase mb-2">Tracking ID (Optional)</label>
                  <input
                    type="text"
                    value={statusUpdate.tracking_id}
                    onChange={(e) => setStatusUpdate({ ...statusUpdate, tracking_id: e.target.value })}
                    className="w-full border-2 border-black p-3 focus:outline-none focus:shadow-brutalist transition-all"
                    placeholder="Enter tracking ID"
                    data-testid="tracking-id-input"
                  />
                </div>
                <div className="flex gap-4">
                  <button
                    type="submit"
                    className="flex-1 bg-brutalist-primary text-white font-bold py-3 px-6 border-2 border-black shadow-brutalist hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-none transition-all"
                    data-testid="update-order-btn"
                  >
                    UPDATE
                  </button>
                  <button
                    type="button"
                    onClick={() => setSelectedOrder(null)}
                    className="flex-1 bg-white text-black font-bold py-3 px-6 border-2 border-black hover:bg-gray-100 transition-all"
                    data-testid="cancel-update-btn"
                  >
                    CANCEL
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Orders List */}
        {loading ? (
          <div className="text-center py-12" data-testid="orders-loading">
            <div className="animate-pulse text-gray-500 font-manrope">Loading orders...</div>
          </div>
        ) : orders.length === 0 ? (
          <div className="text-center py-12 bg-white border-2 border-black p-8" data-testid="no-orders">
            <Package className="w-16 h-16 mx-auto mb-4 text-gray-300" />
            <p className="text-xl font-manrope text-gray-600">No orders yet</p>
          </div>
        ) : (
          <div className="space-y-4" data-testid="orders-list">
            {orders.map((order) => (
              <div key={order.id} className="bg-white border-2 border-black p-6" data-testid={`order-item-${order.id}`}>
                <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-4">
                  <div>
                    <p className="text-sm font-mono uppercase text-gray-600">Order Number</p>
                    <p className="text-xl font-bold font-mono" data-testid={`order-number-${order.id}`}>{order.order_number}</p>
                  </div>
                  <div className="flex gap-2">
                    <span className={`px-3 py-1 border-2 font-bold uppercase text-sm ${getStatusColor(order.payment_status)}`} data-testid={`payment-status-${order.id}`}>
                      {order.payment_status}
                    </span>
                    <span className={`px-3 py-1 border-2 font-bold uppercase text-sm ${getStatusColor(order.order_status)}`} data-testid={`order-status-${order.id}`}>
                      {order.order_status}
                    </span>
                  </div>
                </div>

                <div className="grid md:grid-cols-3 gap-4 mb-4 text-sm">
                  <div>
                    <p className="text-gray-600">Customer</p>
                    <p className="font-bold" data-testid={`customer-name-${order.id}`}>{order.customer_name}</p>
                    <p className="text-gray-600" data-testid={`customer-email-${order.id}`}>{order.customer_email}</p>
                  </div>
                  <div>
                    <p className="text-gray-600">Order Date</p>
                    <p className="font-bold" data-testid={`order-date-${order.id}`}>
                      {new Date(order.created_at).toLocaleDateString()}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-600">Total</p>
                    <p className="font-bold font-mono text-lg" data-testid={`order-total-${order.id}`}>₹{order.total.toFixed(2)}</p>
                  </div>
                </div>

                {order.tracking_id && (
                  <div className="mb-4 p-3 bg-gray-50 border border-gray-300">
                    <p className="text-sm text-gray-600">Tracking ID</p>
                    <p className="font-mono font-bold" data-testid={`tracking-id-${order.id}`}>{order.tracking_id}</p>
                  </div>
                )}

                <div className="flex gap-2 flex-wrap">
                  <button
                    onClick={() => {
                      setSelectedOrder(order);
                      setStatusUpdate({ 
                        order_status: order.order_status, 
                        tracking_id: order.tracking_id || '' 
                      });
                    }}
                    className="flex items-center gap-2 bg-gradient-to-r from-zenvy-primary to-zenvy-secondary text-white font-bold py-2.5 px-5 rounded-xl shadow-medium hover:shadow-large hover:scale-[1.02] transition-all"
                    data-testid={`update-order-status-btn-${order.id}`}
                  >
                    <Package className="w-4 h-4" />
                    Update Status
                  </button>
                  {order.payment_status === 'paid' && !order.shiprocket_order_id && (
                    <button
                      onClick={() => handleCreateShippingLabel(order.id)}
                      disabled={creatingLabel}
                      className="flex items-center gap-2 bg-gradient-to-r from-green-500 to-green-600 text-white font-bold py-2.5 px-5 rounded-xl shadow-medium hover:shadow-large hover:scale-[1.02] transition-all disabled:opacity-50"
                      data-testid={`create-label-btn-${order.id}`}
                    >
                      <Truck className="w-4 h-4" />
                      {creatingLabel ? 'Creating...' : 'Create Shipping Label'}
                    </button>
                  )}
                  {order.shiprocket_order_id && (
                    <div className="flex items-center gap-2 bg-green-100 text-green-800 font-semibold py-2.5 px-5 rounded-xl border-2 border-green-200">
                      <Truck className="w-4 h-4" />
                      Label Created
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};