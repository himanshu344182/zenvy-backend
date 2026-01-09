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
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4" data-testid="admin-login-page">
      <div className="w-full max-w-md">
        <div className="bg-white border-2 border-black p-8">
          <div className="flex items-center justify-center w-16 h-16 bg-brutalist-primary border-2 border-black mx-auto mb-6">
            <Lock className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-3xl font-syne font-bold text-center mb-2" data-testid="admin-login-title">
            ADMIN LOGIN
          </h1>
          <p className="text-center text-gray-600 font-manrope mb-6">Access your admin dashboard</p>

          <form onSubmit={handleLogin} className="space-y-4" data-testid="admin-login-form">
            <div>
              <label className="block text-sm font-mono uppercase mb-2">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full border-2 border-black p-3 focus:outline-none focus:shadow-brutalist transition-all"
                data-testid="admin-username-input"
              />
            </div>
            <div>
              <label className="block text-sm font-mono uppercase mb-2">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full border-2 border-black p-3 focus:outline-none focus:shadow-brutalist transition-all"
                data-testid="admin-password-input"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-brutalist-primary text-white font-bold py-3 px-8 border-2 border-black shadow-brutalist hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-none transition-all disabled:opacity-50"
              data-testid="admin-login-btn"
            >
              {loading ? 'LOGGING IN...' : 'LOGIN'}
            </button>
          </form>
        </div>

        <div className="mt-6 text-center">
          <p className="text-sm text-gray-600 font-manrope">
            Default credentials: admin / admin123
          </p>
        </div>
      </div>
    </div>
  );
};