const { Router } = require('express');

/**
 * Webhook routes
 * @param {import('mongodb').Db} db
 */
function webhookRoutes(db) {
  const router = Router();

  // POST /api/webhooks/shiprocket
  router.post('/webhooks/shiprocket', async (req, res) => {
    try {
      const payload = req.body;

      const orderId = payload.order_id;
      const shipmentStatus = payload.current_status;
      // const trackingUrl = payload.track_url;

      if (orderId) {
        const updateData = {
          updated_at: new Date().toISOString()
        };

        // Map Shiprocket status to our order status (same as Python)
        const statusMapping = {
          'SHIPPED': 'shipped',
          'IN TRANSIT': 'shipped',
          'OUT FOR DELIVERY': 'shipped',
          'DELIVERED': 'delivered',
          'RTO': 'cancelled',
          'LOST': 'cancelled'
        };

        if (statusMapping[shipmentStatus]) {
          updateData.order_status = statusMapping[shipmentStatus];
        }

        await db.collection('orders').updateOne(
          { shiprocket_order_id: String(orderId) },
          { $set: updateData }
        );

        console.log(`Webhook processed for order ${orderId}: ${shipmentStatus}`);
      }

      res.json({ status: 'success' });
    } catch (err) {
      console.error('Webhook error:', err);
      res.json({ status: 'error', message: String(err.message || err) });
    }
  });

  return router;
}

module.exports = webhookRoutes;
