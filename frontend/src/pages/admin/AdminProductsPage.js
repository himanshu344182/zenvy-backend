import React, { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Plus, Edit, Trash2, ArrowLeft } from 'lucide-react';
import api from '../../utils/api';
import { toast } from 'sonner';

export const AdminProductsPage = () => {
  const navigate = useNavigate();
  const [products, setProducts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingProduct, setEditingProduct] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    price: '',
    discount: '0',
    stock: '',
    images: ''
  });

  useEffect(() => {
    const token = localStorage.getItem('admin_token');
    if (!token) {
      navigate('/admin');
      return;
    }
    fetchProducts();
  }, [navigate]);

  const fetchProducts = async () => {
    try {
      const response = await api.get('/admin/products');
      setProducts(response.data);
    } catch (error) {
      console.error('Failed to fetch products:', error);
      if (error.response?.status === 401) {
        toast.error('Session expired');
        localStorage.removeItem('admin_token');
        navigate('/admin');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    const images = formData.images.split('\n').filter(url => url.trim());
    const productData = {
      name: formData.name,
      description: formData.description,
      price: parseFloat(formData.price),
      discount: parseFloat(formData.discount),
      stock: parseInt(formData.stock),
      images: images
    };

    try {
      if (editingProduct) {
        await api.put(`/admin/products/${editingProduct.id}`, productData);
        toast.success('Product updated successfully');
      } else {
        await api.post('/admin/products', productData);
        toast.success('Product created successfully');
      }
      
      setShowForm(false);
      setEditingProduct(null);
      setFormData({
        name: '',
        description: '',
        price: '',
        discount: '0',
        stock: '',
        images: ''
      });
      fetchProducts();
    } catch (error) {
      console.error('Failed to save product:', error);
      toast.error('Failed to save product');
    }
  };

  const handleEdit = (product) => {
    setEditingProduct(product);
    setFormData({
      name: product.name,
      description: product.description,
      price: product.price.toString(),
      discount: product.discount.toString(),
      stock: product.stock.toString(),
      images: product.images.join('\n')
    });
    setShowForm(true);
  };

  const handleDelete = async (productId) => {
    if (!window.confirm('Are you sure you want to delete this product?')) {
      return;
    }

    try {
      await api.delete(`/admin/products/${productId}`);
      toast.success('Product deleted successfully');
      fetchProducts();
    } catch (error) {
      console.error('Failed to delete product:', error);
      toast.error('Failed to delete product');
    }
  };

  const handleCancelForm = () => {
    setShowForm(false);
    setEditingProduct(null);
    setFormData({
      name: '',
      description: '',
      price: '',
      discount: '0',
      stock: '',
      images: ''
    });
  };

  return (
    <div className="min-h-screen bg-gray-50" data-testid="admin-products-page">
      {/* Header */}
      <div className="bg-white border-b-2 border-black">
        <div className="max-w-[1400px] mx-auto p-4 md:p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Link to="/admin/dashboard" className="p-2 hover:bg-gray-100 transition-colors" data-testid="back-to-dashboard-btn">
                <ArrowLeft className="w-6 h-6" />
              </Link>
              <h1 className="text-3xl font-syne font-bold" data-testid="products-title">PRODUCTS</h1>
            </div>
            {!showForm && (
              <button
                onClick={() => setShowForm(true)}
                className="flex items-center gap-2 bg-brutalist-primary text-white font-bold py-3 px-6 border-2 border-black shadow-brutalist hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-none transition-all"
                data-testid="add-product-btn"
              >
                <Plus className="w-5 h-5" />
                ADD PRODUCT
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="max-w-[1400px] mx-auto p-4 md:p-8">
        {/* Form */}
        {showForm && (
          <div className="bg-white border-2 border-black p-6 mb-8" data-testid="product-form">
            <h2 className="font-syne font-bold text-2xl mb-6">
              {editingProduct ? 'EDIT PRODUCT' : 'ADD NEW PRODUCT'}
            </h2>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-mono uppercase mb-2">Product Name *</label>
                <input
                  type="text"
                  name="name"
                  value={formData.name}
                  onChange={handleInputChange}
                  required
                  className="w-full border-2 border-black p-3 focus:outline-none focus:shadow-brutalist transition-all"
                  data-testid="product-name-input"
                />
              </div>
              <div>
                <label className="block text-sm font-mono uppercase mb-2">Description *</label>
                <textarea
                  name="description"
                  value={formData.description}
                  onChange={handleInputChange}
                  required
                  rows="4"
                  className="w-full border-2 border-black p-3 focus:outline-none focus:shadow-brutalist transition-all"
                  data-testid="product-description-input"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-mono uppercase mb-2">Price (₹) *</label>
                  <input
                    type="number"
                    step="0.01"
                    name="price"
                    value={formData.price}
                    onChange={handleInputChange}
                    required
                    className="w-full border-2 border-black p-3 focus:outline-none focus:shadow-brutalist transition-all"
                    data-testid="product-price-input"
                  />
                </div>
                <div>
                  <label className="block text-sm font-mono uppercase mb-2">Discount (%) *</label>
                  <input
                    type="number"
                    step="1"
                    min="0"
                    max="100"
                    name="discount"
                    value={formData.discount}
                    onChange={handleInputChange}
                    required
                    className="w-full border-2 border-black p-3 focus:outline-none focus:shadow-brutalist transition-all"
                    data-testid="product-discount-input"
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm font-mono uppercase mb-2">Stock *</label>
                <input
                  type="number"
                  name="stock"
                  value={formData.stock}
                  onChange={handleInputChange}
                  required
                  className="w-full border-2 border-black p-3 focus:outline-none focus:shadow-brutalist transition-all"
                  data-testid="product-stock-input"
                />
              </div>
              <div>
                <label className="block text-sm font-mono uppercase mb-2">Image URLs * (One per line)</label>
                <textarea
                  name="images"
                  value={formData.images}
                  onChange={handleInputChange}
                  required
                  rows="4"
                  placeholder="https://example.com/image1.jpg&#10;https://example.com/image2.jpg"
                  className="w-full border-2 border-black p-3 focus:outline-none focus:shadow-brutalist transition-all font-mono text-sm"
                  data-testid="product-images-input"
                />
              </div>
              <div className="flex gap-4">
                <button
                  type="submit"
                  className="flex-1 bg-brutalist-primary text-white font-bold py-3 px-6 border-2 border-black shadow-brutalist hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-none transition-all"
                  data-testid="save-product-btn"
                >
                  {editingProduct ? 'UPDATE' : 'CREATE'}
                </button>
                <button
                  type="button"
                  onClick={handleCancelForm}
                  className="flex-1 bg-white text-black font-bold py-3 px-6 border-2 border-black hover:bg-gray-100 transition-all"
                  data-testid="cancel-form-btn"
                >
                  CANCEL
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Products List */}
        {loading ? (
          <div className="text-center py-12" data-testid="products-loading">
            <div className="animate-pulse text-gray-500 font-manrope">Loading products...</div>
          </div>
        ) : products.length === 0 ? (
          <div className="text-center py-12 bg-white border-2 border-black p-8" data-testid="no-products">
            <p className="text-xl font-manrope text-gray-600">No products yet</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" data-testid="products-list">
            {products.map((product) => {
              const finalPrice = product.price * (1 - product.discount / 100);
              return (
                <div
                  key={product.id}
                  className="bg-white border-2 border-black"
                  data-testid={`product-item-${product.id}`}
                >
                  <div className="aspect-square border-b-2 border-black">
                    <img
                      src={product.images[0]}
                      alt={product.name}
                      className="w-full h-full object-cover"
                    />
                  </div>
                  <div className="p-4">
                    <h3 className="font-bold font-manrope text-lg mb-2 line-clamp-2">{product.name}</h3>
                    <p className="text-sm text-gray-600 mb-3 line-clamp-2">{product.description}</p>
                    <div className="flex items-center gap-2 mb-3">
                      <span className="text-xl font-bold font-mono">₹{finalPrice.toFixed(2)}</span>
                      {product.discount > 0 && (
                        <span className="text-sm text-gray-500 line-through">₹{product.price.toFixed(2)}</span>
                      )}
                    </div>
                    <p className="text-sm font-mono mb-4">Stock: {product.stock}</p>
                    <div className="flex gap-2">
                      <button
                        onClick={() => handleEdit(product)}
                        className="flex-1 flex items-center justify-center gap-2 bg-brutalist-secondary text-black font-bold py-2 px-4 border-2 border-black hover:shadow-brutalist transition-all"
                        data-testid={`edit-product-${product.id}`}
                      >
                        <Edit className="w-4 h-4" />
                        EDIT
                      </button>
                      <button
                        onClick={() => handleDelete(product.id)}
                        className="flex-1 flex items-center justify-center gap-2 bg-red-600 text-white font-bold py-2 px-4 border-2 border-black hover:bg-red-700 transition-all"
                        data-testid={`delete-product-${product.id}`}
                      >
                        <Trash2 className="w-4 h-4" />
                        DELETE
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};