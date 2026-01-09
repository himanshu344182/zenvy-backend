import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, Sparkles, TrendingUp } from 'lucide-react';
import api from '../utils/api';
import { SEO } from '../components/SEO';

export const HomePage = () => {
  const [products, setProducts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchProducts = async () => {
      try {
        const response = await api.get('/products?limit=8');
        setProducts(response.data);
      } catch (error) {
        console.error('Failed to fetch products:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchProducts();
  }, []);

  return (
    <div data-testid="home-page">
      <SEO 
        title="ZENVY - Modern E-Commerce Store | Trendy Products Online"
        description="Discover curated collections at ZENVY. Shop daily essentials, electronics, fashion, and trending products. Free shipping on orders over ₹999. Fast delivery across India."
        keywords="online shopping India, ecommerce, buy electronics online, fashion store, home decor, daily essentials, trendy products, ZENVY store"
        url="https://webstore-tracker.preview.emergentagent.com"
      />
      {/* Hero Section */}
      <section className="relative overflow-hidden" data-testid="hero-section">
        <div className="absolute inset-0 bg-gradient-to-br from-zenvy-primary/10 via-zenvy-secondary/10 to-transparent"></div>
        <div className="max-w-[1400px] mx-auto relative">
          <div className="grid md:grid-cols-2 min-h-[80vh] items-center">
            {/* Left: Typography */}
            <div className="flex flex-col justify-center p-8 md:p-12 lg:p-16">
              <div className="inline-block px-4 py-2 bg-zenvy-primary/10 text-zenvy-primary rounded-full text-sm font-semibold mb-6 w-fit">
                ✨ New Arrivals Every Week
              </div>
              <h1 className="text-5xl md:text-7xl font-display font-bold leading-tight mb-6" data-testid="hero-title">
                Welcome to
                <br />
                <span className="bg-gradient-to-r from-zenvy-primary to-zenvy-secondary bg-clip-text text-transparent">
                  ZENVY
                </span>
              </h1>
              <p className="text-lg md:text-xl text-gray-600 mb-8 leading-relaxed max-w-md">
                Discover curated collections of trending products. From daily essentials to Instagram-worthy finds.
              </p>
              <Link
                to="/products"
                className="inline-flex items-center gap-2 bg-gradient-to-r from-zenvy-primary to-zenvy-secondary text-white font-bold py-4 px-8 rounded-full shadow-medium hover:shadow-large hover:scale-105 transition-all duration-200 w-fit"
                data-testid="shop-now-btn"
              >
                Shop Now
                <ArrowRight className="w-5 h-5" />
              </Link>
            </div>

            {/* Right: Hero Image */}
            <div className="relative overflow-hidden h-full">
              <img
                src="https://images.pexels.com/photos/6567607/pexels-photo-6567607.jpeg?auto=compress&cs=tinysrgb&w=800"
                alt="Happy shoppers"
                className="w-full h-full object-cover"
                data-testid="hero-image"
              />
              <div className="absolute inset-0 bg-gradient-to-t from-zenvy-primary/20 to-transparent" />
            </div>
          </div>
        </div>
      </section>

      {/* Marquee */}
      <section className="bg-gradient-to-r from-zenvy-primary to-zenvy-secondary overflow-hidden py-4" data-testid="marquee-section">
        <div className="flex whitespace-nowrap">
          <div className="animate-marquee flex items-center gap-8 text-xl font-display font-semibold text-white">
            <span className="flex items-center gap-2">
              <Sparkles className="w-5 h-5" />
              Trending
            </span>
            <span>•</span>
            <span className="flex items-center gap-2">
              <TrendingUp className="w-5 h-5" />
              Hot Deals
            </span>
            <span>•</span>
            <span>New Arrivals</span>
            <span>•</span>
            <span>Top Rated</span>
            <span>•</span>
            <span className="flex items-center gap-2">
              <Sparkles className="w-5 h-5" />
              Trending
            </span>
            <span>•</span>
            <span className="flex items-center gap-2">
              <TrendingUp className="w-5 h-5" />
              Hot Deals
            </span>
            <span>•</span>
            <span>New Arrivals</span>
            <span>•</span>
            <span>Top Rated</span>
            <span>•</span>
          </div>
          <div className="animate-marquee flex items-center gap-8 text-xl font-display font-semibold text-white">
            <span className="flex items-center gap-2">
              <Sparkles className="w-5 h-5" />
              Trending
            </span>
            <span>•</span>
            <span className="flex items-center gap-2">
              <TrendingUp className="w-5 h-5" />
              Hot Deals
            </span>
            <span>•</span>
            <span>New Arrivals</span>
            <span>•</span>
            <span>Top Rated</span>
            <span>•</span>
            <span className="flex items-center gap-2">
              <Sparkles className="w-5 h-5" />
              Trending
            </span>
            <span>•</span>
            <span className="flex items-center gap-2">
              <TrendingUp className="w-5 h-5" />
              Hot Deals
            </span>
            <span>•</span>
            <span>New Arrivals</span>
            <span>•</span>
            <span>Top Rated</span>
            <span>•</span>
          </div>
        </div>
      </section>

      {/* Featured Products - Bento Grid */}
      <section className="py-16 md:py-24 px-4 md:px-8 bg-gray-50" data-testid="featured-products-section">
        <div className="max-w-[1400px] mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-4xl md:text-5xl font-display font-bold mb-4 bg-gradient-to-r from-zenvy-primary to-zenvy-secondary bg-clip-text text-transparent">
              Featured Collection
            </h2>
            <p className="text-lg text-gray-600">Handpicked products just for you</p>
          </div>

          {loading ? (
            <div className="text-center py-12" data-testid="loading-products">
              <div className="animate-pulse text-gray-500">Loading amazing products...</div>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6" data-testid="products-grid">
              {products.map((product) => {
                const finalPrice = product.price * (1 - product.discount / 100);
                return (
                  <Link
                    key={product.id}
                    to={`/product/${product.id}`}
                    className="group bg-white rounded-2xl overflow-hidden shadow-soft hover:shadow-large transition-all duration-300 hover:scale-[1.02]"
                    data-testid={`product-card-${product.id}`}
                  >
                    <div className="aspect-square overflow-hidden relative">
                      <img
                        src={product.images[0]}
                        alt={product.name}
                        className="w-full h-full object-cover group-hover:scale-110 transition-transform duration-500"
                        data-testid={`product-image-${product.id}`}
                      />
                      {product.discount > 0 && (
                        <div className="absolute top-3 right-3 bg-gradient-to-r from-zenvy-accent to-pink-500 text-white px-3 py-1 rounded-full text-xs font-bold" data-testid={`product-discount-${product.id}`}>
                          {product.discount}% OFF
                        </div>
                      )}
                    </div>
                    <div className="p-4">
                      <h3 className="font-semibold text-gray-900 text-base mb-2 line-clamp-2" data-testid={`product-name-${product.id}`}>
                        {product.name}
                      </h3>
                      <div className="flex items-center gap-2">
                        <span className="text-xl font-bold text-zenvy-primary" data-testid={`product-price-${product.id}`}>
                          ₹{finalPrice.toFixed(2)}
                        </span>
                        {product.discount > 0 && (
                          <span className="text-sm text-gray-400 line-through" data-testid={`product-original-price-${product.id}`}>
                            ₹{product.price.toFixed(2)}
                          </span>
                        )}
                      </div>
                    </div>
                  </Link>
                );
              })}
            </div>
          )}

          <div className="text-center mt-12">
            <Link
              to="/products"
              className="inline-flex items-center gap-2 bg-gradient-to-r from-zenvy-primary to-zenvy-secondary text-white font-bold py-4 px-8 rounded-full shadow-medium hover:shadow-large hover:scale-105 transition-all duration-200"
              data-testid="view-all-btn"
            >
              View All Products
              <ArrowRight className="w-5 h-5" />
            </Link>
          </div>
        </div>
      </section>

      {/* Collections */}
      <section className="py-16 md:py-24 px-4 md:px-8 bg-white" data-testid="collections-section">
        <div className="max-w-[1400px] mx-auto">
          <h2 className="text-4xl md:text-5xl font-display font-bold text-center mb-12 bg-gradient-to-r from-zenvy-primary to-zenvy-secondary bg-clip-text text-transparent">
            Shop by Collection
          </h2>
          <div className="grid md:grid-cols-3 gap-6">
            <div className="group bg-gradient-to-br from-zenvy-primary/5 to-transparent rounded-2xl p-8 hover:shadow-large transition-all cursor-pointer hover:scale-105" data-testid="collection-home">
              <div className="w-12 h-12 rounded-xl bg-zenvy-primary/10 flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                <span className="text-2xl">🏠</span>
              </div>
              <h3 className="text-2xl font-display font-bold mb-2 text-gray-900">For Home</h3>
              <p className="text-gray-600">Essentials that make your space yours</p>
            </div>
            <div className="group bg-gradient-to-br from-zenvy-secondary/5 to-transparent rounded-2xl p-8 hover:shadow-large transition-all cursor-pointer hover:scale-105" data-testid="collection-you">
              <div className="w-12 h-12 rounded-xl bg-zenvy-secondary/10 flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                <span className="text-2xl">✨</span>
              </div>
              <h3 className="text-2xl font-display font-bold mb-2 text-gray-900">For You</h3>
              <p className="text-gray-600">Daily must-haves and trending picks</p>
            </div>
            <div className="group bg-gradient-to-br from-zenvy-accent/5 to-transparent rounded-2xl p-8 hover:shadow-large transition-all cursor-pointer hover:scale-105" data-testid="collection-desk">
              <div className="w-12 h-12 rounded-xl bg-zenvy-accent/10 flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                <span className="text-2xl">💻</span>
              </div>
              <h3 className="text-2xl font-display font-bold mb-2 text-gray-900">For Desk</h3>
              <p className="text-gray-600">Tech and gear to level up your setup</p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};