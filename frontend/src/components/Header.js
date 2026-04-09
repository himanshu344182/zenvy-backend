import React, { useState } from 'react';
import { ShoppingCart, Search, User } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { getCartCount } from '../utils/cart';
import { CartDrawer } from './CartDrawer';

export const Header = () => {
  const [cartOpen, setCartOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const navigate = useNavigate();
  const cartCount = getCartCount();

  const handleSearch = (e) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      navigate(`/products?search=${searchQuery}`);
    }
  };

  return (
    <>
      <header className="bg-white/80 backdrop-blur-md border-b border-gray-200 sticky top-0 z-30 shadow-soft" data-testid="main-header">
        <div className="max-w-[1400px] mx-auto">
          {/* Top bar */}
          <div className="border-b border-gray-100 py-2 px-4 bg-gradient-to-r from-zenvy-primary/5 to-zenvy-secondary/5">
            <div className="flex items-center justify-between">
              <div className="text-xs font-medium text-gray-600">
                ✨ Free shipping on all orders 🔥
              </div>
              <Link 
                to="/track-order" 
                className="text-xs font-medium text-gray-600 hover:text-zenvy-primary transition-colors flex items-center gap-1"
                data-testid="admin-link"
              >
                <User className="w-3.5 h-3.5" />
                Track Your Order
              </Link>
            </div>
          </div>

          {/* Main header */}
          <div className="p-4 md:p-6">
            <div className="flex items-center justify-between gap-4">
              {/* Logo */}
              <Link to="/" data-testid="home-link" className="group">
                <h1 className="text-3xl md:text-4xl font-display font-bold bg-gradient-to-r from-zenvy-primary to-zenvy-secondary bg-clip-text text-transparent group-hover:scale-105 transition-transform">
                  ZENVY
                </h1>
              </Link>

              {/* Search */}
              <form onSubmit={handleSearch} className="hidden md:flex flex-1 max-w-md">
                <div className="relative w-full">
                  <input
                    type="text"
                    placeholder="Search products..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full border border-gray-300 bg-white rounded-full px-5 py-3 pr-12 text-sm focus:ring-2 focus:ring-zenvy-primary focus:border-transparent transition-all shadow-soft"
                    data-testid="search-input"
                  />
                  <button
                    type="submit"
                    className="absolute right-1 top-1/2 -translate-y-1/2 h-9 w-9 rounded-full bg-zenvy-primary hover:bg-zenvy-secondary text-white transition-colors flex items-center justify-center"
                    data-testid="search-btn"
                  >
                    <Search className="w-4 h-4" />
                  </button>
                </div>
              </form>

              {/* Cart */}
              <button
                onClick={() => setCartOpen(true)}
                className="relative p-3 rounded-full bg-gray-50 hover:bg-zenvy-primary hover:text-white transition-all shadow-soft"
                data-testid="cart-icon-btn"
              >
                <ShoppingCart className="w-5 h-5" />
                {cartCount > 0 && (
                  <span 
                    className="absolute -top-1 -right-1 bg-gradient-to-r from-zenvy-accent to-pink-500 text-white w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold"
                    data-testid="cart-count-badge"
                  >
                    {cartCount}
                  </span>
                )}
              </button>
            </div>

            {/* Mobile search */}
            <form onSubmit={handleSearch} className="md:hidden mt-4">
              <div className="relative">
                <input
                  type="text"
                  placeholder="Search products..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full border border-gray-300 bg-white rounded-full px-5 py-3 pr-12 text-sm focus:ring-2 focus:ring-zenvy-primary focus:border-transparent transition-all shadow-soft"
                  data-testid="search-input-mobile"
                />
                <button
                  type="submit"
                  className="absolute right-1 top-1/2 -translate-y-1/2 h-9 w-9 rounded-full bg-zenvy-primary hover:bg-zenvy-secondary text-white transition-colors flex items-center justify-center"
                  data-testid="search-btn-mobile"
                >
                  <Search className="w-4 h-4" />
                </button>
              </div>
            </form>
          </div>
        </div>
      </header>

      <CartDrawer isOpen={cartOpen} onClose={() => setCartOpen(false)} />
    </>
  );
};