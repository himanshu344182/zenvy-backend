import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ArrowLeft, Lock, Key, Save } from 'lucide-react';
import api from '../../utils/api';
import { toast } from 'sonner';

export const AdminSettingsPage = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [passwordForm, setPasswordForm] = useState({
    old_password: '',
    new_password: '',
    confirm_password: ''
  });

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    
    if (passwordForm.new_password !== passwordForm.confirm_password) {
      toast.error('New passwords do not match');
      return;
    }

    if (passwordForm.new_password.length < 6) {
      toast.error('Password must be at least 6 characters');
      return;
    }

    setLoading(true);
    try {
      const formData = new FormData();
      formData.append('old_password', passwordForm.old_password);
      formData.append('new_password', passwordForm.new_password);

      await api.post('/admin/change-password', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      });
      
      toast.success('Password changed successfully!');
      setPasswordForm({
        old_password: '',
        new_password: '',
        confirm_password: ''
      });
    } catch (error) {
      console.error('Password change failed:', error);
      toast.error(error.response?.data?.detail || 'Failed to change password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50" data-testid="admin-settings-page">
      {/* Header */}
      <div className="bg-white border-b border-gray-200 shadow-soft">
        <div className="max-w-[1400px] mx-auto p-4 md:p-6">
          <div className="flex items-center gap-4">
            <Link to="/admin/dashboard" className="p-2 hover:bg-gray-100 rounded-xl transition-colors" data-testid="back-to-dashboard-btn">
              <ArrowLeft className="w-6 h-6" />
            </Link>
            <div>
              <h1 className="text-3xl font-display font-bold bg-gradient-to-r from-zenvy-primary to-zenvy-secondary bg-clip-text text-transparent" data-testid="settings-title">Settings</h1>
              <p className="text-sm text-gray-600 mt-1">Manage your account and API configurations</p>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-[1000px] mx-auto p-4 md:p-8">
        <div className="grid gap-6">
          {/* Change Password */}
          <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-soft">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-zenvy-primary/10 to-zenvy-primary/20 flex items-center justify-center">
                <Lock className="w-5 h-5 text-zenvy-primary" />
              </div>
              <div>
                <h2 className="font-display font-bold text-xl text-gray-900">Change Password</h2>
                <p className="text-sm text-gray-600">Update your admin password</p>
              </div>
            </div>

            <form onSubmit={handlePasswordChange} className="space-y-4 max-w-md">
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">Current Password *</label>
                <input
                  type="password"
                  value={passwordForm.old_password}
                  onChange={(e) => setPasswordForm({ ...passwordForm, old_password: e.target.value })}
                  required
                  className="w-full border-2 border-gray-300 rounded-xl p-3 focus:outline-none focus:ring-2 focus:ring-zenvy-primary focus:border-transparent transition-all"
                  placeholder="Enter current password"
                />
              </div>
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">New Password *</label>
                <input
                  type="password"
                  value={passwordForm.new_password}
                  onChange={(e) => setPasswordForm({ ...passwordForm, new_password: e.target.value })}
                  required
                  minLength={8}
                  className="w-full border-2 border-gray-300 rounded-xl p-3 focus:outline-none focus:ring-2 focus:ring-zenvy-primary focus:border-transparent transition-all"
                  placeholder="Enter new password"
                />
                <div className="mt-2 text-xs text-gray-600 space-y-1">
                  <p className="font-semibold">Password must contain:</p>
                  <ul className="list-disc list-inside space-y-0.5">
                    <li>At least 8 characters</li>
                    <li>One uppercase letter (A-Z)</li>
                    <li>One lowercase letter (a-z)</li>
                    <li>One number (0-9)</li>
                    <li>One special character (@$!%*?&)</li>
                  </ul>
                </div>
              </div>
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">Confirm New Password *</label>
                <input
                  type="password"
                  value={passwordForm.confirm_password}
                  onChange={(e) => setPasswordForm({ ...passwordForm, confirm_password: e.target.value })}
                  required
                  className="w-full border-2 border-gray-300 rounded-xl p-3 focus:outline-none focus:ring-2 focus:ring-zenvy-primary focus:border-transparent transition-all"
                  placeholder="Confirm new password"
                />
              </div>
              <button
                type="submit"
                disabled={loading}
                className="flex items-center gap-2 bg-gradient-to-r from-zenvy-primary to-zenvy-secondary text-white font-bold py-3 px-6 rounded-xl shadow-medium hover:shadow-large hover:scale-[1.02] transition-all disabled:opacity-50"
              >
                <Save className="w-5 h-5" />
                {loading ? 'Saving...' : 'Change Password'}
              </button>
            </form>
          </div>

          {/* API Configuration */}
          <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-soft">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500/10 to-blue-500/20 flex items-center justify-center">
                <Key className="w-5 h-5 text-blue-600" />
              </div>
              <div>
                <h2 className="font-display font-bold text-xl text-gray-900">API Configuration</h2>
                <p className="text-sm text-gray-600">Configure Razorpay and Shiprocket credentials</p>
              </div>
            </div>

            <div className="space-y-4">
              <div className="bg-gradient-to-r from-blue-50 to-purple-50 border-2 border-blue-200 rounded-xl p-4">
                <h3 className="font-bold text-gray-900 mb-2">🔑 Razorpay Configuration</h3>
                <p className="text-sm text-gray-700 mb-3">
                  To enable payments, add your Razorpay keys to <code className="bg-white px-2 py-1 rounded text-xs">/app/backend/.env</code>
                </p>
                <div className="bg-white rounded-lg p-3 font-mono text-xs space-y-1">
                  <div>RAZORPAY_KEY_ID=<span className="text-zenvy-primary">rzp_test_xxxxx</span></div>
                  <div>RAZORPAY_KEY_SECRET=<span className="text-zenvy-primary">your_secret</span></div>
                </div>
                <p className="text-xs text-gray-600 mt-2">
                  Also add <code className="bg-white px-2 py-1 rounded">REACT_APP_RAZORPAY_KEY_ID</code> to <code className="bg-white px-2 py-1 rounded">/app/frontend/.env</code>
                </p>
              </div>

              <div className="bg-gradient-to-r from-green-50 to-teal-50 border-2 border-green-200 rounded-xl p-4">
                <h3 className="font-bold text-gray-900 mb-2">📦 Shiprocket Configuration</h3>
                <p className="text-sm text-gray-700 mb-3">
                  To enable shipping labels, add your Shiprocket credentials to <code className="bg-white px-2 py-1 rounded text-xs">/app/backend/.env</code>
                </p>
                <div className="bg-white rounded-lg p-3 font-mono text-xs space-y-1">
                  <div>SHIPROCKET_EMAIL=<span className="text-green-600">your@email.com</span></div>
                  <div>SHIPROCKET_PASSWORD=<span className="text-green-600">your_password</span></div>
                </div>
              </div>

              <div className="bg-amber-50 border-2 border-amber-200 rounded-xl p-4">
                <p className="text-sm text-gray-700">
                  <strong>⚠️ Important:</strong> After updating .env files, restart backend service:
                </p>
                <code className="block bg-white rounded-lg p-3 font-mono text-xs mt-2">
                  sudo supervisorctl restart backend
                </code>
              </div>

              <div className="flex gap-3">
                <a
                  href="https://dashboard.razorpay.com/app/keys"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 text-center bg-blue-600 text-white font-semibold py-3 px-4 rounded-xl hover:bg-blue-700 transition-colors"
                >
                  Get Razorpay Keys →
                </a>
                <a
                  href="https://app.shiprocket.in/app/#/settings"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 text-center bg-green-600 text-white font-semibold py-3 px-4 rounded-xl hover:bg-green-700 transition-colors"
                >
                  Get Shiprocket Keys →
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
