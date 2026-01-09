import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Package, ShoppingBag, DollarSign, Clock, LogOut } from 'lucide-react';
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
      <div className="bg-white border-b-2 border-black">
        <div className="max-w-[1400px] mx-auto p-4 md:p-6 flex items-center justify-between">
          <h1 className="text-3xl font-syne font-bold" data-testid="dashboard-title">ADMIN DASHBOARD</h1>
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 bg-black text-white font-bold py-2 px-4 border-2 border-black hover:bg-gray-800 transition-colors"
            data-testid="logout-btn"
          >
            <LogOut className="w-4 h-4" />
            LOGOUT
          </button>
        </div>
      </div>

      <div className="max-w-[1400px] mx-auto p-4 md:p-8">
        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8" data-testid="stats-grid">
          <div className="bg-white border-2 border-black p-6" data-testid="stat-products">
            <div className="flex items-center justify-between mb-4">
              <Package className="w-8 h-8 text-brutalist-primary" />
              <span className="text-3xl font-bold font-mono">{stats?.total_products || 0}</span>
            </div>
            <p className="font-manrope font-bold">Total Products</p>
          </div>

          <div className="bg-white border-2 border-black p-6" data-testid="stat-orders">
            <div className="flex items-center justify-between mb-4">
              <ShoppingBag className="w-8 h-8 text-brutalist-primary" />
              <span className="text-3xl font-bold font-mono">{stats?.total_orders || 0}</span>
            </div>
            <p className="font-manrope font-bold">Total Orders</p>
          </div>

          <div className="bg-white border-2 border-black p-6" data-testid="stat-pending">
            <div className="flex items-center justify-between mb-4">
              <Clock className="w-8 h-8 text-yellow-600" />
              <span className="text-3xl font-bold font-mono">{stats?.pending_orders || 0}</span>
            </div>
            <p className="font-manrope font-bold">Pending Orders</p>
          </div>

          <div className="bg-white border-2 border-black p-6" data-testid="stat-revenue">
            <div className="flex items-center justify-between mb-4">
              <DollarSign className="w-8 h-8 text-green-600" />
              <span className="text-3xl font-bold font-mono">₹{stats?.total_revenue?.toFixed(0) || 0}</span>
            </div>
            <p className="font-manrope font-bold">Total Revenue</p>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="bg-white border-2 border-black p-6" data-testid="quick-actions">
          <h2 className="font-syne font-bold text-2xl mb-6">QUICK ACTIONS</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Link
              to="/admin/products"
              className="flex items-center justify-between bg-brutalist-primary text-white font-bold py-4 px-6 border-2 border-black shadow-brutalist hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-none transition-all"
              data-testid="manage-products-btn"
            >
              <span>MANAGE PRODUCTS</span>
              <Package className="w-5 h-5" />
            </Link>
            <Link
              to="/admin/orders"
              className="flex items-center justify-between bg-brutalist-secondary text-black font-bold py-4 px-6 border-2 border-black shadow-brutalist hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-none transition-all"
              data-testid="manage-orders-btn"
            >
              <span>MANAGE ORDERS</span>
              <ShoppingBag className="w-5 h-5" />
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};