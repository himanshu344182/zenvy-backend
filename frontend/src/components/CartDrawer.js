import React, { useState, useEffect } from 'react';
import { ShoppingCart, X, Plus, Minus } from 'lucide-react';
import { getCart, updateCartItem, removeFromCart, getCartTotal } from '../utils/cart';
import { useNavigate } from 'react-router-dom';

export const CartDrawer = ({ isOpen, onClose }) => {
  const [cart, setCart] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    if (isOpen) {
      setCart(getCart());
    }
  }, [isOpen]);

  const handleUpdateQuantity = (productId, newQuantity) => {
    const updatedCart = updateCartItem(productId, newQuantity);
    setCart(updatedCart);
  };

  const handleRemove = (productId) => {
    const updatedCart = removeFromCart(productId);
    setCart(updatedCart);
  };

  const handleCheckout = () => {
    onClose();
    navigate('/checkout');
  };

  if (!isOpen) return null;

  const total = getCartTotal();

  return (
    <div className="fixed inset-0 z-50">
      <div 
        className="absolute inset-0 bg-black/30 backdrop-blur-sm" 
        onClick={onClose}
        data-testid="cart-overlay"
      />
      <div 
        className="absolute right-0 top-0 h-full w-full md:w-[420px] bg-white shadow-large flex flex-col"
        data-testid="cart-drawer"
      >
        {/* Header */}
        <div className="p-6 border-b border-gray-200 flex items-center justify-between bg-gradient-to-r from-zenvy-primary/5 to-zenvy-secondary/5">
          <h2 className="text-2xl font-display font-bold text-gray-900" data-testid="cart-title">Your Cart</h2>
          <button
            onClick={onClose}
            className="p-2 rounded-full hover:bg-gray-100 transition-colors"
            data-testid="cart-close-btn"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Cart Items */}
        <div className="flex-1 overflow-y-auto p-6" data-testid="cart-items-container">
          {cart.length === 0 ? (
            <div className="text-center py-16" data-testid="cart-empty-message">
              <div className="w-20 h-20 mx-auto mb-4 rounded-full bg-gray-100 flex items-center justify-center">
                <ShoppingCart className="w-10 h-10 text-gray-400" />
              </div>
              <p className="text-gray-500 font-medium">Your cart is empty</p>
              <p className="text-sm text-gray-400 mt-2">Add some products to get started</p>
            </div>
          ) : (
            <div className="space-y-4">
              {cart.map((item) => (
                <div 
                  key={item.product_id} 
                  className="bg-gray-50 rounded-xl p-4 hover:shadow-medium transition-shadow"
                  data-testid={`cart-item-${item.product_id}`}
                >
                  <div className="flex gap-4">
                    <img
                      src={item.image}
                      alt={item.product_name}
                      className="w-20 h-20 object-cover rounded-lg"
                      data-testid={`cart-item-image-${item.product_id}`}
                    />
                    <div className="flex-1">
                      <h3 className="font-semibold text-gray-900 mb-1 line-clamp-2" data-testid={`cart-item-name-${item.product_id}`}>
                        {item.product_name}
                      </h3>
                      <p className="text-lg font-bold text-zenvy-primary" data-testid={`cart-item-price-${item.product_id}`}>
                        ₹{item.price.toFixed(2)}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center justify-between mt-4">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleUpdateQuantity(item.product_id, item.quantity - 1)}
                        className="w-8 h-8 rounded-full border border-gray-300 flex items-center justify-center hover:border-zenvy-primary hover:text-zenvy-primary transition-colors"
                        data-testid={`cart-item-decrease-${item.product_id}`}
                      >
                        <Minus className="w-4 h-4" />
                      </button>
                      <span className="px-4 py-1 text-sm font-bold text-gray-900" data-testid={`cart-item-quantity-${item.product_id}`}>
                        {item.quantity}
                      </span>
                      <button
                        onClick={() => handleUpdateQuantity(item.product_id, item.quantity + 1)}
                        className="w-8 h-8 rounded-full border border-gray-300 flex items-center justify-center hover:border-zenvy-primary hover:text-zenvy-primary transition-colors"
                        data-testid={`cart-item-increase-${item.product_id}`}
                      >
                        <Plus className="w-4 h-4" />
                      </button>
                    </div>
                    <button
                      onClick={() => handleRemove(item.product_id)}
                      className="text-sm text-red-500 hover:text-red-700 font-medium transition-colors"
                      data-testid={`cart-item-remove-${item.product_id}`}
                    >
                      Remove
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        {cart.length > 0 && (
          <div className="p-6 border-t border-gray-200 bg-white">
            <div className="flex justify-between items-center mb-4">
              <span className="text-lg font-semibold text-gray-700">Total</span>
              <span className="text-2xl font-bold text-gray-900" data-testid="cart-total">₹{total.toFixed(2)}</span>
            </div>
            <button
              onClick={handleCheckout}
              className="w-full bg-gradient-to-r from-zenvy-primary to-zenvy-secondary text-white font-bold py-4 px-8 rounded-xl shadow-medium hover:shadow-large hover:scale-[1.02] transition-all duration-200"
              data-testid="cart-checkout-btn"
            >
              Proceed to Checkout
            </button>
          </div>
        )}
      </div>
    </div>
  );
};