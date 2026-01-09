import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Lock } from 'lucide-react';
import api from '../../utils/api';
import { toast } from 'sonner';

export const AdminLoginPage = () => {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await api.post('/admin/login', { username, password });
      localStorage.setItem('admin_token', response.data.access_token);
      toast.success('Login successful!');
      navigate('/admin/dashboard');
    } catch (error) {
      console.error('Login failed:', error);
      toast.error('Invalid credentials');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-zenvy-primary/10 via-zenvy-secondary/10 to-white flex items-center justify-center p-4" data-testid="admin-login-page">
      <div className="w-full max-w-md">
        <div className="bg-white rounded-2xl shadow-large p-8">
          <div className="flex items-center justify-center w-16 h-16 bg-gradient-to-r from-zenvy-primary to-zenvy-secondary rounded-2xl mx-auto mb-6">
            <Lock className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-3xl font-display font-bold text-center mb-2 bg-gradient-to-r from-zenvy-primary to-zenvy-secondary bg-clip-text text-transparent" data-testid="admin-login-title">
            Admin Login
          </h1>
          <p className="text-center text-gray-600 mb-8">Access your ZENVY dashboard</p>

          <form onSubmit={handleLogin} className="space-y-5" data-testid="admin-login-form">
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full border-2 border-gray-300 rounded-xl p-3 focus:outline-none focus:ring-2 focus:ring-zenvy-primary focus:border-transparent transition-all"
                data-testid="admin-username-input"
                placeholder="Enter username"
              />
            </div>
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full border-2 border-gray-300 rounded-xl p-3 focus:outline-none focus:ring-2 focus:ring-zenvy-primary focus:border-transparent transition-all"
                data-testid="admin-password-input"
                placeholder="Enter password"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-zenvy-primary to-zenvy-secondary text-white font-bold py-3.5 px-8 rounded-xl shadow-medium hover:shadow-large hover:scale-[1.02] transition-all disabled:opacity-50 disabled:hover:scale-100"
              data-testid="admin-login-btn"
            >
              {loading ? 'Logging in...' : 'Login to Dashboard'}
            </button>
          </form>
        </div>

        <div className="mt-6 text-center bg-white/60 backdrop-blur rounded-xl p-4">
          <p className="text-sm text-gray-600">
            Default: <span className="font-semibold text-gray-900">admin / admin123</span>
          </p>
        </div>
      </div>
    </div>
  );
};