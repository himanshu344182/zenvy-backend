// Cart management using localStorage

export const getCart = () => {
  const cart = localStorage.getItem('cart');
  return cart ? JSON.parse(cart) : [];
};

export const addToCart = (product, quantity = 1) => {
  const cart = getCart();
  const existingItem = cart.find(item => item.product_id === product.id);
  
  if (existingItem) {
    existingItem.quantity += quantity;
  } else {
    cart.push({
      product_id: product.id,
      product_name: product.name,
      price: product.price * (1 - product.discount / 100),
      quantity: quantity,
      image: product.images[0] || ''
    });
  }
  
  localStorage.setItem('cart', JSON.stringify(cart));
  return cart;
};

export const updateCartItem = (productId, quantity) => {
  const cart = getCart();
  const item = cart.find(item => item.product_id === productId);
  
  if (item) {
    if (quantity <= 0) {
      return removeFromCart(productId);
    }
    item.quantity = quantity;
    localStorage.setItem('cart', JSON.stringify(cart));
  }
  
  return cart;
};

export const removeFromCart = (productId) => {
  const cart = getCart();
  const newCart = cart.filter(item => item.product_id !== productId);
  localStorage.setItem('cart', JSON.stringify(newCart));
  return newCart;
};

export const clearCart = () => {
  localStorage.removeItem('cart');
  return [];
};

export const getCartTotal = () => {
  const cart = getCart();
  return cart.reduce((total, item) => total + (item.price * item.quantity), 0);
};

export const getCartCount = () => {
  const cart = getCart();
  return cart.reduce((count, item) => count + item.quantity, 0);
};