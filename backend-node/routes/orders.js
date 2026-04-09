const { Router } = require('express');
const { v4: uuidv4 } = require('uuid');
const Razorpay = require('razorpay');
const { createShiprocketShipment, SHIPROCKET_EMAIL, SHIPROCKET_PASSWORD } = require('../utils/shiprocket');
const { sendOrderConfirmationEmail } = require('../utils/mail');

const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID || '';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || '';

/**
 * Order routes (public)
 * @param {import('mongodb').Db} db
 */
function orderRoutes(db) {
  const router = Router();

  // POST /api/orders
  router.post('/orders', async (req, res) => {
    try {
      const data = req.body;

      // Validate required fields
      const requiredFields = [
        'customer_name', 'customer_email', 'customer_phone',
        'shipping_address', 'shipping_city', 'shipping_state',
        'shipping_pincode', 'items', 'subtotal', 'total'
      ];
      for (const field of requiredFields) {
        if (data[field] === undefined || data[field] === null) {
          return res.status(422).json({ detail: `Missing required field: ${field}` });
        }
      }

      const now = new Date().toISOString();
      const order = {
        id: uuidv4(),
        order_number: `ORD-${uuidv4().replace(/-/g, '').substring(0, 8).toUpperCase()}`,
        customer_name: data.customer_name,
        customer_email: data.customer_email,
        customer_phone: data.customer_phone,
        shipping_address: data.shipping_address,
        shipping_city: data.shipping_city,
        shipping_state: data.shipping_state,
        shipping_pincode: data.shipping_pincode,
        items: data.items,
        subtotal: data.subtotal,
        shipping_cost: data.shipping_cost || 0,
        total: data.total,
        payment_id: null,
        razorpay_order_id: null,
        razorpay_payment_id: null,
        razorpay_signature: null,
        payment_status: 'pending',
        order_status: 'pending',
        tracking_id: null,
        shiprocket_order_id: null,
        created_at: now,
        updated_at: now
      };

      // Create Razorpay order if keys are configured
      if (RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET) {
        try {
          const razorpayClient = new Razorpay({
            key_id: RAZORPAY_KEY_ID,
            key_secret: RAZORPAY_KEY_SECRET
          });

          const amountInPaise = Math.round(order.total * 100);
          const razorpayOrder = await razorpayClient.orders.create({
            amount: amountInPaise,
            currency: 'INR',
            receipt: order.order_number,
            payment_capture: 1
          });
          order.razorpay_order_id = razorpayOrder.id;
        } catch (err) {
          console.error('Razorpay order creation failed:', err.message);
        }
      }

      await db.collection('orders').insertOne({ ...order });

      // Return without _id (Mongo adds it)
      const { _id, ...orderWithoutId } = order;
      res.status(200).json(orderWithoutId);
    } catch (err) {
      console.error('Error creating order:', err);
      res.status(500).json({ detail: 'Internal server error' });
    }
  });

  // POST /api/orders/verify-payment
  router.post('/orders/verify-payment', async (req, res) => {
    try {
      if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) {
        return res.status(400).json({ detail: 'Razorpay not configured' });
      }

      const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

      if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
        return res.status(422).json({ detail: 'Missing payment verification fields' });
      }

      const razorpayClient = new Razorpay({
        key_id: RAZORPAY_KEY_ID,
        key_secret: RAZORPAY_KEY_SECRET
      });

      // Verify signature — throws on failure
      const isValid = Razorpay.validateWebhookSignature(
        razorpay_order_id + '|' + razorpay_payment_id,
        razorpay_signature,
        RAZORPAY_KEY_SECRET
      );

      if (!isValid) {
        return res.status(400).json({ detail: 'Payment verification failed' });
      }

      // Update order
      await db.collection('orders').updateOne(
        { razorpay_order_id },
        {
          $set: {
            payment_status: 'paid',
            order_status: 'confirmed',
            razorpay_payment_id,
            razorpay_signature,
            updated_at: new Date().toISOString()
          }
        }
      );

      // Reduce stock for each item
      const order = await db
        .collection('orders')
        .findOne({ razorpay_order_id }, { projection: { _id: 0 } });

      if (order) {
        for (const item of order.items) {
          await db.collection('products').updateOne(
            { id: item.product_id },
            { $inc: { stock: -item.quantity } }
          );
        }

        // Send order confirmation email via Zoho
        sendOrderConfirmationEmail(order).catch((err) =>
          console.error('Email send error:', err.message)
        );

        // Auto-create Shiprocket shipment if configured
        if (SHIPROCKET_EMAIL && SHIPROCKET_PASSWORD) {
          try {
            await createShiprocketShipment(order, db);
          } catch (err) {
            console.error('Auto-shipment creation failed:', err.message);
          }
        }
      }

      res.json({ status: 'success', message: 'Payment verified' });
    } catch (err) {
      console.error('Payment verification failed:', err.message);
      res.status(400).json({ detail: 'Payment verification failed' });
    }
  });

  // GET /api/orders/track/:order_number
  router.get('/orders/track/:order_number', async (req, res) => {
    try {
      const order = await db
        .collection('orders')
        .findOne(
          { order_number: req.params.order_number.toUpperCase() },
          { projection: { _id: 0 } }
        );

      if (!order) {
        return res.status(404).json({ detail: 'Order not found' });
      }

      res.json(order);
    } catch (err) {
      console.error('Error tracking order:', err);
      res.status(500).json({ detail: 'Internal server error' });
    }
  });

  return router;
}

module.exports = orderRoutes;
