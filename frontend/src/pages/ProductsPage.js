import React, { useEffect, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { SlidersHorizontal } from 'lucide-react';
import api from '../utils/api';
import { SEO } from '../components/SEO';

export const ProductsPage = () => {
  const [searchParams] = useSearchParams();
  const [products, setProducts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [minPrice, setMinPrice] = useState('');
  const [maxPrice, setMaxPrice] = useState('');
  const [filterOpen, setFilterOpen] = useState(false);

  const searchQuery = searchParams.get('search') || '';

  useEffect(() => {
    fetchProducts();
  }, [searchQuery, minPrice, maxPrice]);

  const fetchProducts = async () => {
    setLoading(true);
    try {
      let url = '/products?limit=100';
      if (searchQuery) url += `&search=${searchQuery}`;
      if (minPrice) url += `&min_price=${minPrice}`;
      if (maxPrice) url += `&max_price=${maxPrice}`;
      
      const response = await api.get(url);
      setProducts(response.data);
    } catch (error) {
      console.error('Failed to fetch products:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleApplyFilters = () => {
    fetchProducts();
    setFilterOpen(false);
  };

  const handleClearFilters = () => {
    setMinPrice('');
    setMaxPrice('');
    fetchProducts();
  };

  return (
    <div className="min-h-screen" data-testid="products-page">
      <SEO 
        title={searchQuery ? `Search: ${searchQuery} - ZENVY` : "All Products - ZENVY | Shop Online"}
        description={searchQuery ? `Search results for ${searchQuery} at ZENVY` : "Browse all products at ZENVY. Find electronics, fashion, home essentials and more. Best prices with free shipping over ₹999."}
        keywords="shop online, buy products, electronics, fashion, home decor, daily essentials"
        url={`https://webstore-tracker.preview.emergentagent.com/products${searchQuery ? `?search=${searchQuery}` : ''}`}
      />
      <div className="max-w-[1400px] mx-auto p-4 md:p-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl md:text-6xl font-syne font-bold tracking-tight mb-4" data-testid="products-title">
            {searchQuery ? `SEARCH: ${searchQuery}` : 'ALL PRODUCTS'}
          </h1>
          <div className="flex items-center gap-4">
            <button
              onClick={() => setFilterOpen(!filterOpen)}
              className="flex items-center gap-2 bg-white border-2 border-black px-4 py-2 font-bold hover:shadow-brutalist transition-all"
              data-testid="filter-toggle-btn"
            >
              <SlidersHorizontal className="w-5 h-5" />
              FILTERS
            </button>
            <span className="font-manrope text-gray-600" data-testid="product-count">
              {products.length} products found
            </span>
          </div>
        </div>

        <div className="flex gap-8">
          {/* Filters Sidebar */}
          <div className={`${filterOpen ? 'block' : 'hidden'} md:block w-full md:w-64 flex-shrink-0`}>
            <div className="border-2 border-black bg-white p-6 sticky top-24" data-testid="filters-panel">
              <h3 className="font-syne font-bold text-xl mb-4">PRICE RANGE</h3>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-mono uppercase mb-2">Min Price</label>
                  <input
                    type="number"
                    placeholder="0"
                    value={minPrice}
                    onChange={(e) => setMinPrice(e.target.value)}
                    className="w-full border-2 border-black p-2 focus:outline-none focus:shadow-brutalist transition-all"
                    data-testid="min-price-input"
                  />
                </div>
                <div>
                  <label className="block text-sm font-mono uppercase mb-2">Max Price</label>
                  <input
                    type="number"
                    placeholder="10000"
                    value={maxPrice}
                    onChange={(e) => setMaxPrice(e.target.value)}
                    className="w-full border-2 border-black p-2 focus:outline-none focus:shadow-brutalist transition-all"
                    data-testid="max-price-input"
                  />
                </div>
                <div className="flex flex-col gap-2">
                  <button
                    onClick={handleApplyFilters}
                    className="w-full bg-brutalist-primary text-white font-bold py-2 px-4 border-2 border-black hover:shadow-brutalist transition-all"
                    data-testid="apply-filters-btn"
                  >
                    APPLY
                  </button>
                  <button
                    onClick={handleClearFilters}
                    className="w-full bg-white text-black font-bold py-2 px-4 border-2 border-black hover:bg-gray-100 transition-all"
                    data-testid="clear-filters-btn"
                  >
                    CLEAR
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Products Grid */}
          <div className="flex-1">
            {loading ? (
              <div className="text-center py-12" data-testid="loading-indicator">
                <div className="animate-pulse text-gray-500 font-manrope">Loading products...</div>
              </div>
            ) : products.length === 0 ? (
              <div className="text-center py-12 border-2 border-black p-8" data-testid="no-products-message">
                <p className="text-xl font-manrope text-gray-600">No products found</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6" data-testid="products-grid">
                {products.map((product) => {
                  const finalPrice = product.price * (1 - product.discount / 100);
                  return (
                    <Link
                      key={product.id}
                      to={`/product/${product.id}`}
                      className="border-2 border-black bg-white hover:shadow-brutalist-lg transition-all duration-300 group"
                      data-testid={`product-card-${product.id}`}
                    >
                      <div className="aspect-square overflow-hidden border-b-2 border-black">
                        <img
                          src={product.images[0]}
                          alt={product.name}
                          className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                          data-testid={`product-image-${product.id}`}
                        />
                      </div>
                      <div className="p-4">
                        <h3 className="font-bold font-manrope text-lg mb-2 line-clamp-2" data-testid={`product-name-${product.id}`}>
                          {product.name}
                        </h3>
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-2xl font-bold font-mono" data-testid={`product-price-${product.id}`}>
                            ₹{finalPrice.toFixed(2)}
                          </span>
                          {product.discount > 0 && (
                            <>
                              <span className="text-sm text-gray-500 line-through">
                                ₹{product.price.toFixed(2)}
                              </span>
                              <span className="bg-brutalist-accent text-white px-2 py-1 text-xs font-bold">
                                {product.discount}% OFF
                              </span>
                            </>
                          )}
                        </div>
                        {product.stock > 0 ? (
                          <p className="text-sm text-green-600 font-mono mt-2" data-testid={`product-stock-${product.id}`}>
                            IN STOCK ({product.stock})
                          </p>
                        ) : (
                          <p className="text-sm text-red-600 font-mono mt-2" data-testid={`product-out-of-stock-${product.id}`}>
                            OUT OF STOCK
                          </p>
                        )}
                      </div>
                    </Link>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};