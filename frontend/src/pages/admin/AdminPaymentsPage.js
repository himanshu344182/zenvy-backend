import React, { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ArrowLeft, DollarSign, CheckCircle, XCircle, Clock, Download } from 'lucide-react';
import api from '../../utils/api';
import { toast } from 'sonner';

export const AdminPaymentsPage = () => {
  const navigate = useNavigate();
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all'); // all, paid, pending, failed

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

  const getStatusIcon = (status) => {
    switch (status) {
      case 'paid':
        return <CheckCircle className="w-5 h-5 text-green-600" />;
      case 'failed':
        return <XCircle className="w-5 h-5 text-red-600" />;
      default:
        return <Clock className="w-5 h-5 text-amber-600" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'paid':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'failed':
        return 'bg-red-100 text-red-800 border-red-200';
      default:
        return 'bg-amber-100 text-amber-800 border-amber-200';
    }
  };

  const filteredOrders = orders.filter(order => {
    if (filter === 'all') return true;
    return order.payment_status === filter;
  });

  const totalRevenue = orders
    .filter(o => o.payment_status === 'paid')
    .reduce((sum, o) => sum + o.total, 0);

  const pendingAmount = orders
    .filter(o => o.payment_status === 'pending')
    .reduce((sum, o) => sum + o.total, 0);

  return (
    <div className="min-h-screen bg-gray-50" data-testid="admin-payments-page">
      {/* Header */}
      <div className="bg-white border-b border-gray-200 shadow-soft">
        <div className="max-w-[1400px] mx-auto p-4 md:p-6">
          <div className="flex items-center gap-4">
            <Link to="/admin/dashboard" className="p-2 hover:bg-gray-100 rounded-xl transition-colors" data-testid="back-to-dashboard-btn">
              <ArrowLeft className="w-6 h-6" />
            </Link>
            <div>
              <h1 className="text-3xl font-display font-bold bg-gradient-to-r from-zenvy-primary to-zenvy-secondary bg-clip-text text-transparent" data-testid="payments-title">Payments & Transactions</h1>
              <p className="text-sm text-gray-600 mt-1">Track all payment activities</p>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-[1400px] mx-auto p-4 md:p-8">
        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-soft">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-xl bg-green-100 flex items-center justify-center">
                <DollarSign className="w-5 h-5 text-green-600" />
              </div>
              <span className="font-semibold text-gray-700">Total Revenue</span>
            </div>
            <p className="text-3xl font-bold text-gray-900">₹{totalRevenue.toFixed(2)}</p>
            <p className="text-sm text-gray-500 mt-1">From successful payments</p>
          </div>

          <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-soft">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-xl bg-amber-100 flex items-center justify-center">
                <Clock className="w-5 h-5 text-amber-600" />
              </div>
              <span className="font-semibold text-gray-700">Pending Payments</span>
            </div>
            <p className="text-3xl font-bold text-gray-900">₹{pendingAmount.toFixed(2)}</p>
            <p className="text-sm text-gray-500 mt-1">Awaiting payment</p>
          </div>

          <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-soft">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-xl bg-blue-100 flex items-center justify-center">
                <CheckCircle className="w-5 h-5 text-blue-600" />
              </div>
              <span className="font-semibold text-gray-700">Total Transactions</span>
            </div>
            <p className="text-3xl font-bold text-gray-900">{orders.length}</p>
            <p className="text-sm text-gray-500 mt-1">All payment attempts</p>
          </div>
        </div>

        {/* Filters */}
        <div className="bg-white rounded-2xl border border-gray-200 p-4 shadow-soft mb-6">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="font-semibold text-gray-700">Filter by status:</span>
            <button
              onClick={() => setFilter('all')}
              className={`px-4 py-2 rounded-xl font-medium transition-all ${
                filter === 'all'
                  ? 'bg-zenvy-primary text-white shadow-medium'
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              All ({orders.length})
            </button>
            <button
              onClick={() => setFilter('paid')}
              className={`px-4 py-2 rounded-xl font-medium transition-all ${
                filter === 'paid'
                  ? 'bg-green-600 text-white shadow-medium'
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              Paid ({orders.filter(o => o.payment_status === 'paid').length})
            </button>
            <button
              onClick={() => setFilter('pending')}
              className={`px-4 py-2 rounded-xl font-medium transition-all ${
                filter === 'pending'
                  ? 'bg-amber-600 text-white shadow-medium'
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              Pending ({orders.filter(o => o.payment_status === 'pending').length})
            </button>
            <button
              onClick={() => setFilter('failed')}
              className={`px-4 py-2 rounded-xl font-medium transition-all ${
                filter === 'failed'
                  ? 'bg-red-600 text-white shadow-medium'
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              Failed ({orders.filter(o => o.payment_status === 'failed').length})
            </button>
          </div>
        </div>

        {/* Transactions List */}
        {loading ? (
          <div className="text-center py-12" data-testid="payments-loading">
            <div className="animate-pulse text-gray-500">Loading transactions...</div>
          </div>
        ) : filteredOrders.length === 0 ? (
          <div className="text-center py-12 bg-white rounded-2xl border border-gray-200 p-8" data-testid="no-transactions">
            <DollarSign className="w-16 h-16 mx-auto mb-4 text-gray-300" />
            <p className="text-xl text-gray-600">No transactions found</p>
          </div>
        ) : (
          <div className="bg-white rounded-2xl border border-gray-200 shadow-soft overflow-hidden" data-testid="transactions-list">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-700">Order Number</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-700">Customer</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-700">Date</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-700">Amount</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-700">Payment Status</th>
                    <th className="px-6 py-4 text-left text-sm font-semibold text-gray-700">Payment ID</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {filteredOrders.map((order) => (
                    <tr key={order.id} className="hover:bg-gray-50 transition-colors" data-testid={`transaction-${order.id}`}>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          {getStatusIcon(order.payment_status)}
                          <span className="font-mono font-semibold text-gray-900">{order.order_number}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div>
                          <p className="font-semibold text-gray-900">{order.customer_name}</p>
                          <p className="text-sm text-gray-600">{order.customer_email}</p>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-gray-700">
                        {new Date(order.created_at).toLocaleDateString('en-IN', {
                          day: '2-digit',
                          month: 'short',
                          year: 'numeric'
                        })}
                      </td>
                      <td className="px-6 py-4">
                        <span className="font-bold text-lg text-gray-900">₹{order.total.toFixed(2)}</span>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold border ${getStatusColor(order.payment_status)}`}>
                          {order.payment_status.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        {order.razorpay_payment_id ? (
                          <span className="text-sm font-mono text-gray-600">{order.razorpay_payment_id}</span>
                        ) : (
                          <span className="text-sm text-gray-400">-</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
