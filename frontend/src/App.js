import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Toaster } from 'sonner';
import './App.css';

import { Header } from './components/Header';
import { HomePage } from './pages/HomePage';
import { ProductsPage } from './pages/ProductsPage';
import { ProductDetailPage } from './pages/ProductDetailPage';
import { CheckoutPage } from './pages/CheckoutPage';
import { OrderConfirmationPage } from './pages/OrderConfirmationPage';
import { OrderTrackingPage } from './pages/OrderTrackingPage';
import { AdminLoginPage } from './pages/admin/AdminLoginPage';
import { AdminDashboardPage } from './pages/admin/AdminDashboardPage';
import { AdminProductsPage } from './pages/admin/AdminProductsPage';
import { AdminOrdersPage } from './pages/admin/AdminOrdersPage';
import { AdminPaymentsPage } from './pages/admin/AdminPaymentsPage';
import { AdminSettingsPage } from './pages/admin/AdminSettingsPage';
import { ProtectedAdminRoute } from './components/ProtectedAdminRoute';

function App() {
  return (
    <BrowserRouter>
      <div className="App">
        {/* Noise texture overlay */}
        <div className="noise-overlay" />
        
        <Routes>
          {/* Customer Routes */}
          <Route path="/" element={<><Header /><HomePage /></>} />
          <Route path="/products" element={<><Header /><ProductsPage /></>} />
          <Route path="/product/:id" element={<><Header /><ProductDetailPage /></>} />
          <Route path="/checkout" element={<><Header /><CheckoutPage /></>} />
          <Route path="/order-confirmation/:orderNumber" element={<><Header /><OrderConfirmationPage /></>} />
          <Route path="/track-order" element={<><Header /><OrderTrackingPage /></>} />
          
          {/* Admin Routes - Protected */}
          <Route path="/admin" element={<AdminLoginPage />} />
          <Route path="/admin/dashboard" element={<ProtectedAdminRoute><AdminDashboardPage /></ProtectedAdminRoute>} />
          <Route path="/admin/products" element={<ProtectedAdminRoute><AdminProductsPage /></ProtectedAdminRoute>} />
          <Route path="/admin/orders" element={<ProtectedAdminRoute><AdminOrdersPage /></ProtectedAdminRoute>} />
          <Route path="/admin/payments" element={<ProtectedAdminRoute><AdminPaymentsPage /></ProtectedAdminRoute>} />
          <Route path="/admin/settings" element={<ProtectedAdminRoute><AdminSettingsPage /></ProtectedAdminRoute>} />
        </Routes>
        
        <Toaster 
          position="top-right"
          toastOptions={{
            style: {
              border: '2px solid #000',
              fontFamily: 'Manrope, sans-serif',
              fontWeight: 'bold'
            }
          }}
        />
      </div>
    </BrowserRouter>
  );
}

export default App;