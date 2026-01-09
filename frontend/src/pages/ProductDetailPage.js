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
    <div className="min-h-screen" data-testid="product-detail-page">
      <div className="max-w-[1400px] mx-auto p-4 md:p-8">
        <div className="grid md:grid-cols-2 gap-8 md:gap-12">
          {/* Images */}
          <div className="space-y-4" data-testid="product-images-section">
            <div className="aspect-square border-2 border-black overflow-hidden">
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
                    className={`aspect-square border-2 overflow-hidden ${
                      selectedImage === index ? 'border-brutalist-primary' : 'border-black'
                    }`}
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
              <h1 className="text-4xl md:text-5xl font-syne font-bold tracking-tight mb-4" data-testid="product-title">
                {product.name}
              </h1>
              <div className="flex items-center gap-4 flex-wrap">
                <span className="text-4xl font-bold font-mono" data-testid="product-price-display">
                  ₹{finalPrice.toFixed(2)}
                </span>
                {product.discount > 0 && (
                  <>
                    <span className="text-xl text-gray-500 line-through" data-testid="product-original-price-display">
                      ₹{product.price.toFixed(2)}
                    </span>
                    <span className="bg-brutalist-accent text-white px-3 py-1 text-sm font-bold" data-testid="product-discount-display">
                      {product.discount}% OFF
                    </span>
                  </>
                )}
              </div>
            </div>

            {/* Stock Status */}
            <div className="border-2 border-black p-4 bg-white">
              {product.stock > 0 ? (
                <div className="flex items-center gap-2 text-green-600" data-testid="stock-available">
                  <Check className="w-5 h-5" />
                  <span className="font-bold font-mono">IN STOCK - {product.stock} available</span>
                </div>
              ) : (
                <div className="flex items-center gap-2 text-red-600" data-testid="stock-unavailable">
                  <AlertCircle className="w-5 h-5" />
                  <span className="font-bold font-mono">OUT OF STOCK</span>
                </div>
              )}
            </div>

            {/* Quantity Selector */}
            {product.stock > 0 && (
              <div className="space-y-2">
                <label className="block text-sm font-mono uppercase">Quantity</label>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setQuantity(Math.max(1, quantity - 1))}
                    className="px-4 py-2 border-2 border-black font-bold hover:bg-black hover:text-white transition-colors"
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
                    className="w-20 px-4 py-2 border-2 border-black text-center font-mono font-bold focus:outline-none focus:shadow-brutalist"
                    data-testid="quantity-input"
                  />
                  <button
                    onClick={() => setQuantity(Math.min(product.stock, quantity + 1))}
                    className="px-4 py-2 border-2 border-black font-bold hover:bg-black hover:text-white transition-colors"
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
              className="w-full bg-brutalist-primary text-white font-bold py-4 px-8 border-2 border-black shadow-brutalist hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-none transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              data-testid="add-to-cart-btn"
            >
              <ShoppingCart className="w-5 h-5" />
              {product.stock > 0 ? 'ADD TO CART' : 'OUT OF STOCK'}
            </button>

            {/* Description */}
            <div className="border-2 border-black p-6 bg-gray-50" data-testid="product-description">
              <h3 className="font-syne font-bold text-xl mb-3">DESCRIPTION</h3>
              <p className="font-manrope leading-relaxed whitespace-pre-wrap">{product.description}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};