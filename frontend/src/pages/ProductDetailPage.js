import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ShoppingCart, Check, AlertCircle } from 'lucide-react';
import api from '../utils/api';
import { addToCart } from '../utils/cart';
import { toast } from 'sonner';

export const ProductDetailPage = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [product, setProduct] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedImage, setSelectedImage] = useState(0);
  const [quantity, setQuantity] = useState(1);

  useEffect(() => {
    const fetchProduct = async () => {
      try {
        const response = await api.get(`/products/${id}`);
        setProduct(response.data);
      } catch (error) {
        console.error('Failed to fetch product:', error);
        toast.error('Product not found');
        navigate('/products');
      } finally {
        setLoading(false);
      }
    };
    fetchProduct();
  }, [id, navigate]);

  const handleAddToCart = () => {
    if (product && product.stock > 0) {
      addToCart(product, quantity);
      toast.success('Added to cart!');
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center" data-testid="loading-page">
        <div className="animate-pulse text-gray-500 font-manrope">Loading product...</div>
      </div>
    );
  }

  if (!product) {
    return null;
  }

  const finalPrice = product.price * (1 - product.discount / 100);

  return (
    <div className="min-h-screen bg-gray-50" data-testid="product-detail-page">
      <div className="max-w-[1400px] mx-auto p-4 md:p-8">
        <div className="grid md:grid-cols-2 gap-8 md:gap-12">
          {/* Images */}
          <div className="space-y-4" data-testid="product-images-section">
            <div className="aspect-square rounded-2xl overflow-hidden shadow-medium">
              <img
                src={product.images[selectedImage]}
                alt={product.name}
                className="w-full h-full object-cover"
                data-testid="product-main-image"
              />
            </div>
            {product.images.length > 1 && (
              <div className="grid grid-cols-4 gap-4">
                {product.images.map((image, index) => (
                  <button
                    key={index}
                    onClick={() => setSelectedImage(index)}
                    className={`aspect-square rounded-xl overflow-hidden ${
                      selectedImage === index ? 'ring-4 ring-zenvy-primary shadow-medium' : 'ring-2 ring-gray-200 hover:ring-gray-300'
                    } transition-all`}
                    data-testid={`product-thumbnail-${index}`}
                  >
                    <img
                      src={image}
                      alt={`${product.name} ${index + 1}`}
                      className="w-full h-full object-cover"
                    />
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Details */}
          <div className="space-y-6" data-testid="product-details-section">
            <div>
              <h1 className="text-4xl md:text-5xl font-display font-bold mb-4" data-testid="product-title">
                {product.name}
              </h1>
              <div className="flex items-center gap-4 flex-wrap">
                <span className="text-4xl font-bold bg-gradient-to-r from-zenvy-primary to-zenvy-secondary bg-clip-text text-transparent" data-testid="product-price-display">
                  ₹{finalPrice.toFixed(2)}
                </span>
                {product.discount > 0 && (
                  <>
                    <span className="text-xl text-gray-400 line-through" data-testid="product-original-price-display">
                      ₹{product.price.toFixed(2)}
                    </span>
                    <span className="bg-gradient-to-r from-zenvy-accent to-pink-500 text-white px-4 py-1.5 rounded-full text-sm font-bold" data-testid="product-discount-display">
                      {product.discount}% OFF
                    </span>
                  </>
                )}
              </div>
            </div>

            {/* Stock Status */}
            <div className="rounded-xl bg-gradient-to-r from-green-50 to-emerald-50 border border-green-200 p-4">
              {product.stock > 0 ? (
                <div className="flex items-center gap-2 text-green-700" data-testid="stock-available">
                  <Check className="w-5 h-5" />
                  <span className="font-semibold">In Stock - {product.stock} available</span>
                </div>
              ) : (
                <div className="flex items-center gap-2 text-red-600" data-testid="stock-unavailable">
                  <AlertCircle className="w-5 h-5" />
                  <span className="font-semibold">Out of Stock</span>
                </div>
              )}
            </div>

            {/* Quantity Selector */}
            {product.stock > 0 && (
              <div className="space-y-2">
                <label className="block text-sm font-semibold text-gray-700">Quantity</label>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => setQuantity(Math.max(1, quantity - 1))}
                    className="w-10 h-10 rounded-full border-2 border-gray-300 font-bold hover:border-zenvy-primary hover:text-zenvy-primary transition-colors flex items-center justify-center"
                    data-testid="quantity-decrease-btn"
                  >
                    -
                  </button>
                  <input
                    type="number"
                    min="1"
                    max={product.stock}
                    value={quantity}
                    onChange={(e) => setQuantity(Math.max(1, Math.min(product.stock, parseInt(e.target.value) || 1)))}
                    className="w-20 px-4 py-2 border-2 border-gray-300 rounded-lg text-center font-bold focus:outline-none focus:ring-2 focus:ring-zenvy-primary focus:border-transparent"
                    data-testid="quantity-input"
                  />
                  <button
                    onClick={() => setQuantity(Math.min(product.stock, quantity + 1))}
                    className="w-10 h-10 rounded-full border-2 border-gray-300 font-bold hover:border-zenvy-primary hover:text-zenvy-primary transition-colors flex items-center justify-center"
                    data-testid="quantity-increase-btn"
                  >
                    +
                  </button>
                </div>
              </div>
            )}

            {/* Add to Cart Button */}
            <button
              onClick={handleAddToCart}
              disabled={product.stock === 0}
              className="w-full bg-gradient-to-r from-zenvy-primary to-zenvy-secondary text-white font-bold py-4 px-8 rounded-xl shadow-medium hover:shadow-large hover:scale-[1.02] transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100 flex items-center justify-center gap-2 text-lg"
              data-testid="add-to-cart-btn"
            >
              <ShoppingCart className="w-5 h-5" />
              {product.stock > 0 ? 'Add to Cart' : 'Out of Stock'}
            </button>

            {/* Description */}
            <div className="rounded-xl bg-white border border-gray-200 p-6 shadow-soft" data-testid="product-description">
              <h3 className="font-display font-bold text-xl mb-3 text-gray-900">Description</h3>
              <p className="text-gray-600 leading-relaxed whitespace-pre-wrap">{product.description}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};