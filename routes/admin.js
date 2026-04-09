const { Router } = require('express');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const { createAccessToken, verifyToken, hashPassword, verifyPassword } = require('../utils/auth');
const { createShiprocketShipment, SHIPROCKET_EMAIL, SHIPROCKET_PASSWORD } = require('../utils/shiprocket');
const { sendShippingNotificationEmail } = require('../utils/mail');

/**
 * Admin routes (auth + protected CRUD)
 * @param {import('mongodb').Db} db
 */
function adminRoutes(db) {
  const router = Router();

  // Rate limiters
  const loginLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { detail: 'Too many login attempts, please try again later' },
    standardHeaders: true,
    legacyHeaders: false
  });

  const changePasswordLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 3,
    message: { detail: 'Too many attempts, please try again later' },
    standardHeaders: true,
    legacyHeaders: false
  });

  // ============ AUTH ROUTES ============

  // POST /api/admin/login
  router.post('/admin/login', loginLimiter, async (req, res) => {
    try {
      const { username, password } = req.body;

      if (!username || !password) {
        return res.status(422).json({ detail: 'Username and password are required' });
      }

      const admin = await db.collection('admins').findOne({ username }, { projection: { _id: 0 } });
      if (!admin || !verifyPassword(password, admin.password_hash)) {
        return res.status(401).json({ detail: 'Invalid credentials' });
      }

      const accessToken = createAccessToken({ sub: admin.username });
      res.json({ access_token: accessToken, token_type: 'bearer' });
    } catch (err) {
      console.error('Login error:', err);
      res.status(500).json({ detail: 'Internal server error' });
    }
  });

  // POST /api/admin/create
  router.post('/admin/create', async (req, res) => {
    try {
      const { username, password } = req.body;

      if (!username || !password) {
        return res.status(422).json({ detail: 'Username and password are required' });
      }

      // Password validation (same rules as Python)
      if (password.length < 8) {
        return res.status(422).json({ detail: [{ msg: 'Password must be at least 8 characters' }] });
      }
      if (!/[a-z]/.test(password)) {
        return res.status(422).json({ detail: [{ msg: 'Password must contain at least one lowercase letter' }] });
      }
      if (!/[A-Z]/.test(password)) {
        return res.status(422).json({ detail: [{ msg: 'Password must contain at least one uppercase letter' }] });
      }
      if (!/\d/.test(password)) {
        return res.status(422).json({ detail: [{ msg: 'Password must contain at least one digit' }] });
      }
      if (!/[@$!%*?&]/.test(password)) {
        return res.status(422).json({ detail: [{ msg: 'Password must contain at least one special character (@$!%*?&)' }] });
      }

      const existing = await db.collection('admins').findOne({ username });
      if (existing) {
        return res.status(400).json({ detail: 'Admin already exists' });
      }

      const now = new Date().toISOString();
      const admin = {
        id: uuidv4(),
        username,
        password_hash: hashPassword(password),
        created_at: now
      };

      await db.collection('admins').insertOne({ ...admin });
      res.json({ message: 'Admin created successfully' });
    } catch (err) {
      console.error('Create admin error:', err);
      res.status(500).json({ detail: 'Internal server error' });
    }
  });

  // POST /api/admin/change-password
  router.post('/admin/change-password', changePasswordLimiter, verifyToken, async (req, res) => {
    try {
      const { old_password, new_password } = req.body;

      if (!old_password || !new_password) {
        return res.status(422).json({ detail: 'old_password and new_password are required' });
      }

      // Password validation
      if (new_password.length < 8) {
        return res.status(400).json({ detail: 'Password must be at least 8 characters' });
      }
      if (!/[a-z]/.test(new_password)) {
        return res.status(400).json({ detail: 'Password must contain at least one lowercase letter' });
      }
      if (!/[A-Z]/.test(new_password)) {
        return res.status(400).json({ detail: 'Password must contain at least one uppercase letter' });
      }
      if (!/\d/.test(new_password)) {
        return res.status(400).json({ detail: 'Password must contain at least one digit' });
      }
      if (!/[@$!%*?&]/.test(new_password)) {
        return res.status(400).json({ detail: 'Password must contain at least one special character (@$!%*?&)' });
      }

      const admin = await db.collection('admins').findOne({ username: req.username }, { projection: { _id: 0 } });
      if (!admin) {
        return res.status(404).json({ detail: 'Admin not found' });
      }

      if (!verifyPassword(old_password, admin.password_hash)) {
        return res.status(401).json({ detail: 'Invalid old password' });
      }

      await db.collection('admins').updateOne(
        { username: req.username },
        { $set: { password_hash: hashPassword(new_password) } }
      );

      res.json({ message: 'Password changed successfully' });
    } catch (err) {
      console.error('Change password error:', err);
      res.status(500).json({ detail: 'Internal server error' });
    }
  });

  // ============ PROTECTED PRODUCT ROUTES ============

  // GET /api/admin/products
  router.get('/admin/products', verifyToken, async (req, res) => {
    try {
      const products = await db
        .collection('products')
        .find({}, { projection: { _id: 0 } })
        .limit(1000)
        .toArray();

      res.json(products);
    } catch (err) {
      console.error('Error fetching admin products:', err);
      res.status(500).json({ detail: 'Internal server error' });
    }
  });

  // POST /api/admin/products
  router.post('/admin/products', verifyToken, async (req, res) => {
    try {
      const { name, description, price, discount = 0, stock, images } = req.body;

      if (!name || !description || price === undefined || stock === undefined || !images) {
        return res.status(422).json({ detail: 'Missing required product fields' });
      }

      const now = new Date().toISOString();
      const product = {
        id: uuidv4(),
        name,
        description,
        price,
        discount,
        stock,
        images,
        created_at: now,
        updated_at: now
      };

      await db.collection('products').insertOne({ ...product });
      res.json(product);
    } catch (err) {
      console.error('Error creating product:', err);
      res.status(500).json({ detail: 'Internal server error' });
    }
  });

  // PUT /api/admin/products/:product_id
  router.put('/admin/products/:product_id', verifyToken, async (req, res) => {
    try {
      const updateData = {};
      const allowedFields = ['name', 'description', 'price', 'discount', 'stock', 'images'];
      for (const field of allowedFields) {
        if (req.body[field] !== undefined && req.body[field] !== null) {
          updateData[field] = req.body[field];
        }
      }

      if (Object.keys(updateData).length === 0) {
        return res.status(400).json({ detail: 'No data to update' });
      }

      updateData.updated_at = new Date().toISOString();

      const result = await db.collection('products').updateOne(
        { id: req.params.product_id },
        { $set: updateData }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json({ detail: 'Product not found' });
      }

      const product = await db
        .collection('products')
        .findOne({ id: req.params.product_id }, { projection: { _id: 0 } });

      res.json(product);
    } catch (err) {
      console.error('Error updating product:', err);
      res.status(500).json({ detail: 'Internal server error' });
    }
  });

  // DELETE /api/admin/products/:product_id
  router.delete('/admin/products/:product_id', verifyToken, async (req, res) => {
    try {
      const result = await db.collection('products').deleteOne({ id: req.params.product_id });
      if (result.deletedCount === 0) {
        return res.status(404).json({ detail: 'Product not found' });
      }
      res.json({ message: 'Product deleted successfully' });
    } catch (err) {
      console.error('Error deleting product:', err);
      res.status(500).json({ detail: 'Internal server error' });
    }
  });

  // ============ PROTECTED ORDER ROUTES ============

  // GET /api/admin/orders
  router.get('/admin/orders', verifyToken, async (req, res) => {
    try {
      const orders = await db
        .collection('orders')
        .find({}, { projection: { _id: 0 } })
        .sort({ created_at: -1 })
        .limit(1000)
        .toArray();

      // Fix numeric IDs from Shiprocket (same as Python)
      for (const order of orders) {
        if (order.tracking_id !== null && order.tracking_id !== undefined) {
          order.tracking_id = String(order.tracking_id);
        }
        if (order.shiprocket_order_id !== null && order.shiprocket_order_id !== undefined) {
          order.shiprocket_order_id = String(order.shiprocket_order_id);
        }
      }

      res.json(orders);
    } catch (err) {
      console.error('Error fetching orders:', err);
      res.status(500).json({ detail: 'Internal server error' });
    }
  });

  // PUT /api/admin/orders/:order_id
  router.put('/admin/orders/:order_id', verifyToken, async (req, res) => {
    try {
      const { order_status, tracking_id } = req.body;

      if (!order_status) {
        return res.status(422).json({ detail: 'order_status is required' });
      }

      const updateData = {
        order_status,
        updated_at: new Date().toISOString()
      };
      if (tracking_id) {
        updateData.tracking_id = tracking_id;
      }

      const result = await db.collection('orders').updateOne(
        { id: req.params.order_id },
        { $set: updateData }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json({ detail: 'Order not found' });
      }

      // If order is shipped, send shipping notification email
      if (order_status === 'shipped') {
        const order = await db.collection('orders').findOne(
          { id: req.params.order_id },
          { projection: { _id: 0 } }
        );
        if (order) {
          sendShippingNotificationEmail(order).catch((err) =>
            console.error('Shipping email error:', err.message)
          );
        }
      }

      res.json({ message: 'Order updated successfully' });
    } catch (err) {
      console.error('Error updating order:', err);
      res.status(500).json({ detail: 'Internal server error' });
    }
  });

  // GET /api/admin/stats
  router.get('/admin/stats', verifyToken, async (req, res) => {
    try {
      const totalProducts = await db.collection('products').countDocuments({});
      const totalOrders = await db.collection('orders').countDocuments({});
      const pendingOrders = await db.collection('orders').countDocuments({ order_status: 'pending' });
      const confirmedOrders = await db.collection('orders').countDocuments({ order_status: 'confirmed' });

      // Calculate total revenue from paid orders
      const pipeline = [
        { $match: { payment_status: 'paid' } },
        { $group: { _id: null, total_revenue: { $sum: '$total' } } }
      ];
      const revenueResult = await db.collection('orders').aggregate(pipeline).toArray();
      const totalRevenue = revenueResult.length > 0 ? revenueResult[0].total_revenue : 0;

      res.json({
        total_products: totalProducts,
        total_orders: totalOrders,
        pending_orders: pendingOrders,
        confirmed_orders: confirmedOrders,
        total_revenue: totalRevenue
      });
    } catch (err) {
      console.error('Error fetching stats:', err);
      res.status(500).json({ detail: 'Internal server error' });
    }
  });

  // POST /api/admin/shiprocket/create-order
  router.post('/admin/shiprocket/create-order', verifyToken, async (req, res) => {
    try {
      const { order_id } = req.query;

      if (!SHIPROCKET_EMAIL || !SHIPROCKET_PASSWORD) {
        return res.status(400).json({ detail: 'Shiprocket not configured' });
      }

      if (!order_id) {
        return res.status(422).json({ detail: 'order_id query parameter is required' });
      }

      const order = await db.collection('orders').findOne({ id: order_id }, { projection: { _id: 0 } });
      if (!order) {
        return res.status(404).json({ detail: 'Order not found' });
      }

      const result = await createShiprocketShipment(order, db);
      res.json({ message: 'Shiprocket order created', data: result });
    } catch (err) {
      console.error('Shiprocket error:', err.message);
      res.status(500).json({ detail: String(err.message || err) });
    }
  });

  return router;
}

module.exports = adminRoutes;
