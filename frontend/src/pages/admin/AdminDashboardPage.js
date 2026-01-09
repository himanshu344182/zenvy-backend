import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Package, ShoppingBag, DollarSign, Clock, LogOut, Settings } from 'lucide-react';
import api from '../../utils/api';
import { toast } from 'sonner';

export const AdminDashboardPage = () => {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('admin_token');
    if (!token) {
      navigate('/admin');
      return;
    }

    fetchStats();
  }, [navigate]);

  const fetchStats = async () => {
    try {
      const response = await api.get('/admin/stats');
      setStats(response.data);
    } catch (error) {
      console.error('Failed to fetch stats:', error);
      if (error.response?.status === 401) {
        toast.error('Session expired');
        handleLogout();
      }
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('admin_token');
    navigate('/admin');
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center" data-testid="dashboard-loading">
        <div className="animate-pulse text-gray-500 font-manrope">Loading dashboard...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50" data-testid="admin-dashboard-page">
      {/* Header */}
      <div className="bg-white border-b border-gray-200 shadow-soft">
        <div className="max-w-[1400px] mx-auto p-4 md:p-6 flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-display font-bold bg-gradient-to-r from-zenvy-primary to-zenvy-secondary bg-clip-text text-transparent" data-testid="dashboard-title">Admin Dashboard</h1>
            <p className="text-sm text-gray-600 mt-1">Manage your ZENVY store</p>
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 bg-gray-900 text-white font-semibold py-2.5 px-5 rounded-xl hover:bg-gray-800 transition-colors shadow-soft"
            data-testid="logout-btn"
          >
            <LogOut className="w-4 h-4" />
            Logout
          </button>
        </div>
      </div>

      <div className="max-w-[1400px] mx-auto p-4 md:p-8">
        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8" data-testid="stats-grid">
          <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-soft hover:shadow-medium transition-shadow" data-testid="stat-products">
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-zenvy-primary/10 to-zenvy-primary/20 flex items-center justify-center">
                <Package className="w-6 h-6 text-zenvy-primary" />
              </div>
              <span className="text-3xl font-bold text-gray-900">{stats?.total_products || 0}</span>
            </div>
            <p className="font-semibold text-gray-700">Total Products</p>
            <p className="text-xs text-gray-500 mt-1">Active inventory items</p>
          </div>

          <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-soft hover:shadow-medium transition-shadow" data-testid="stat-orders">
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500/10 to-blue-500/20 flex items-center justify-center">
                <ShoppingBag className="w-6 h-6 text-blue-600" />
              </div>
              <span className="text-3xl font-bold text-gray-900">{stats?.total_orders || 0}</span>
            </div>
            <p className="font-semibold text-gray-700">Total Orders</p>
            <p className="text-xs text-gray-500 mt-1">All time orders</p>
          </div>

          <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-soft hover:shadow-medium transition-shadow" data-testid="stat-pending">
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-amber-500/10 to-amber-500/20 flex items-center justify-center">
                <Clock className="w-6 h-6 text-amber-600" />
              </div>
              <span className="text-3xl font-bold text-gray-900">{stats?.pending_orders || 0}</span>
            </div>
            <p className="font-semibold text-gray-700">Pending Orders</p>
            <p className="text-xs text-gray-500 mt-1">Needs attention</p>
          </div>

          <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-soft hover:shadow-medium transition-shadow" data-testid="stat-revenue">
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-green-500/10 to-green-500/20 flex items-center justify-center">
                <DollarSign className="w-6 h-6 text-green-600" />
              </div>
              <span className="text-3xl font-bold text-gray-900">₹{stats?.total_revenue?.toFixed(0) || 0}</span>
            </div>
            <p className="font-semibold text-gray-700">Total Revenue</p>
            <p className="text-xs text-gray-500 mt-1">From paid orders</p>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-soft" data-testid="quick-actions">
          <h2 className="font-display font-bold text-2xl mb-6 text-gray-900">Quick Actions</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <Link
              to="/admin/products"
              className="group relative overflow-hidden bg-gradient-to-br from-zenvy-primary to-zenvy-secondary text-white font-bold py-5 px-6 rounded-xl shadow-medium hover:shadow-large transition-all hover:scale-[1.02] flex items-center justify-between"
              data-testid="manage-products-btn"
            >
              <span className="text-lg">Products</span>
              <Package className="w-6 h-6 group-hover:scale-110 transition-transform" />
            </Link>
            <Link
              to="/admin/orders"
              className="group relative overflow-hidden bg-gradient-to-br from-blue-500 to-blue-600 text-white font-bold py-5 px-6 rounded-xl shadow-medium hover:shadow-large transition-all hover:scale-[1.02] flex items-center justify-between"
              data-testid="manage-orders-btn"
            >
              <span className="text-lg">Orders</span>
              <ShoppingBag className="w-6 h-6 group-hover:scale-110 transition-transform" />
            </Link>
            <Link
              to="/admin/payments"
              className="group relative overflow-hidden bg-gradient-to-br from-green-500 to-green-600 text-white font-bold py-5 px-6 rounded-xl shadow-medium hover:shadow-large transition-all hover:scale-[1.02] flex items-center justify-between"
              data-testid="view-payments-btn"
            >
              <span className="text-lg">Payments</span>
              <DollarSign className="w-6 h-6 group-hover:scale-110 transition-transform" />
            </Link>
            <Link
              to="/admin/settings"
              className="group relative overflow-hidden bg-gradient-to-br from-gray-700 to-gray-800 text-white font-bold py-5 px-6 rounded-xl shadow-medium hover:shadow-large transition-all hover:scale-[1.02] flex items-center justify-between"
              data-testid="settings-btn"
            >
              <span className="text-lg">Settings</span>
              <Settings className="w-6 h-6 group-hover:scale-110 transition-transform" />
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};