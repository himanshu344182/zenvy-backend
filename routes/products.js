const { Router } = require('express');
const { v4: uuidv4 } = require('uuid');

/**
 * Product routes (public)
 * @param {import('mongodb').Db} db
 */
function productRoutes(db) {
  const router = Router();

  // GET /api/products
  router.get('/products', async (req, res) => {
    try {
      const { search, min_price, max_price, limit = '100' } = req.query;
      const query = {};

      if (search) {
        query.name = { $regex: search, $options: 'i' };
      }

      if (min_price !== undefined || max_price !== undefined) {
        query.price = {};
        if (min_price !== undefined) query.price.$gte = parseFloat(min_price);
        if (max_price !== undefined) query.price.$lte = parseFloat(max_price);
      }

      const products = await db
        .collection('products')
        .find(query, { projection: { _id: 0 } })
        .limit(parseInt(limit, 10))
        .toArray();

      res.json(products);
    } catch (err) {
      console.error('Error fetching products:', err);
      res.status(500).json({ detail: 'Internal server error' });
    }
  });

  // GET /api/products/:product_id
  router.get('/products/:product_id', async (req, res) => {
    try {
      const product = await db
        .collection('products')
        .findOne({ id: req.params.product_id }, { projection: { _id: 0 } });

      if (!product) {
        return res.status(404).json({ detail: 'Product not found' });
      }

      res.json(product);
    } catch (err) {
      console.error('Error fetching product:', err);
      res.status(500).json({ detail: 'Internal server error' });
    }
  });

  return router;
}

module.exports = productRoutes;
