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
        className="absolute inset-0 bg-black bg-opacity-50" 
        onClick={onClose}
        data-testid="cart-overlay"
      />
      <div 
        className="absolute right-0 top-0 h-full w-full md:w-[500px] bg-white border-l-2 border-black flex flex-col"
        data-testid="cart-drawer"
      >
        {/* Header */}
        <div className="p-6 border-b-2 border-black flex items-center justify-between">
          <h2 className="text-2xl font-syne font-bold" data-testid="cart-title">YOUR CART</h2>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 transition-colors"
            data-testid="cart-close-btn"
          >
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Cart Items */}
        <div className="flex-1 overflow-y-auto p-6" data-testid="cart-items-container">
          {cart.length === 0 ? (
            <div className="text-center py-12" data-testid="cart-empty-message">
              <ShoppingCart className="w-16 h-16 mx-auto mb-4 text-gray-300" />
              <p className="text-gray-500 font-manrope">Your cart is empty</p>
            </div>
          ) : (
            <div className="space-y-4">
              {cart.map((item) => (
                <div 
                  key={item.product_id} 
                  className="border-2 border-black p-4 bg-white"
                  data-testid={`cart-item-${item.product_id}`}
                >
                  <div className="flex gap-4">
                    <img
                      src={item.image}
                      alt={item.product_name}
                      className="w-20 h-20 object-cover border-2 border-black"
                      data-testid={`cart-item-image-${item.product_id}`}
                    />
                    <div className="flex-1">
                      <h3 className="font-bold font-manrope mb-2" data-testid={`cart-item-name-${item.product_id}`}>
                        {item.product_name}
                      </h3>
                      <p className="text-lg font-bold" data-testid={`cart-item-price-${item.product_id}`}>
                        ₹{item.price.toFixed(2)}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center justify-between mt-4">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleUpdateQuantity(item.product_id, item.quantity - 1)}
                        className="p-2 border-2 border-black hover:bg-black hover:text-white transition-colors"
                        data-testid={`cart-item-decrease-${item.product_id}`}
                      >
                        <Minus className="w-4 h-4" />
                      </button>
                      <span className="px-4 py-2 border-2 border-black font-bold font-mono" data-testid={`cart-item-quantity-${item.product_id}`}>
                        {item.quantity}
                      </span>
                      <button
                        onClick={() => handleUpdateQuantity(item.product_id, item.quantity + 1)}
                        className="p-2 border-2 border-black hover:bg-black hover:text-white transition-colors"
                        data-testid={`cart-item-increase-${item.product_id}`}
                      >
                        <Plus className="w-4 h-4" />
                      </button>
                    </div>
                    <button
                      onClick={() => handleRemove(item.product_id)}
                      className="text-red-600 hover:text-red-800 font-bold"
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
          <div className="p-6 border-t-2 border-black bg-gray-50">
            <div className="flex justify-between items-center mb-4">
              <span className="text-xl font-bold font-syne">TOTAL</span>
              <span className="text-2xl font-bold font-mono" data-testid="cart-total">₹{total.toFixed(2)}</span>
            </div>
            <button
              onClick={handleCheckout}
              className="w-full bg-brutalist-primary text-white font-bold py-4 px-8 border-2 border-black shadow-brutalist hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-none transition-all duration-200"
              data-testid="cart-checkout-btn"
            >
              CHECKOUT
            </button>
          </div>
        )}
      </div>
    </>
  );
};