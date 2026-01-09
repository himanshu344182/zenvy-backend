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
      <header className="border-b-2 border-black bg-white sticky top-0 z-30" data-testid="main-header">
        <div className="max-w-[1400px] mx-auto">
          {/* Top bar */}
          <div className="border-b-2 border-black py-2 px-4">
            <div className="flex items-center justify-between">
              <div className="text-xs font-mono uppercase tracking-widest">
                FREE SHIPPING ON ORDERS OVER ₹999
              </div>
              <Link 
                to="/admin" 
                className="text-xs font-mono uppercase tracking-widest hover:text-brutalist-primary transition-colors"
                data-testid="admin-link"
              >
                <User className="w-4 h-4 inline mr-1" />
                ADMIN
              </Link>
            </div>
          </div>

          {/* Main header */}
          <div className="p-4 md:p-6">
            <div className="flex items-center justify-between gap-4">
              {/* Logo */}
              <Link to="/" data-testid="home-link">
                <h1 className="text-3xl md:text-4xl font-syne font-bold tracking-tighter">
                  EVERYTHING<span className="text-brutalist-primary">.</span>
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
                    className="w-full border-2 border-black bg-white p-3 pr-12 text-base focus:ring-0 focus:outline-none focus:shadow-brutalist transition-all"
                    data-testid="search-input"
                  />
                  <button
                    type="submit"
                    className="absolute right-0 top-0 h-full px-4 border-l-2 border-black hover:bg-black hover:text-white transition-colors"
                    data-testid="search-btn"
                  >
                    <Search className="w-5 h-5" />
                  </button>
                </div>
              </form>

              {/* Cart */}
              <button
                onClick={() => setCartOpen(true)}
                className="relative p-3 border-2 border-black hover:bg-black hover:text-white transition-colors"
                data-testid="cart-icon-btn"
              >
                <ShoppingCart className="w-6 h-6" />
                {cartCount > 0 && (
                  <span 
                    className="absolute -top-2 -right-2 bg-brutalist-secondary text-black w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold border-2 border-black"
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
                  className="w-full border-2 border-black bg-white p-3 pr-12 text-base focus:ring-0 focus:outline-none focus:shadow-brutalist transition-all"
                  data-testid="search-input-mobile"
                />
                <button
                  type="submit"
                  className="absolute right-0 top-0 h-full px-4 border-l-2 border-black hover:bg-black hover:text-white transition-colors"
                  data-testid="search-btn-mobile"
                >
                  <Search className="w-5 h-5" />
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