const axios = require('axios');

const SHIPROCKET_EMAIL = process.env.SHIPROCKET_EMAIL || '';
const SHIPROCKET_PASSWORD = process.env.SHIPROCKET_PASSWORD || '';

/**
 * Create a Shiprocket shipment for an order.
 * Mirrors the Python `create_shiprocket_shipment_internal` function exactly.
 * @param {object} order - The order document from MongoDB
 * @param {object} db - The MongoDB database instance
 * @returns {object} Shiprocket API response
 */
async function createShiprocketShipment(order, db) {
  // 1. Authenticate
  const authResponse = await axios.post(
    'https://apiv2.shiprocket.in/v1/external/auth/login',
    {
      email: SHIPROCKET_EMAIL,
      password: SHIPROCKET_PASSWORD
    },
    { timeout: 30000 }
  );

  const token = authResponse.data.token;
  if (!token) {
    throw new Error(`Shiprocket auth failed: ${JSON.stringify(authResponse.data)}`);
  }

  // 2. Prepare shipment payload
  const fullName = order.customer_name.trim();
  const nameParts = fullName.split(' ', 2);
  const firstName = nameParts[0];
  const lastName = nameParts.length > 1 ? nameParts[1] : 'Customer';

  // Handle created_at which may be a string or Date
  let orderDate;
  if (typeof order.created_at === 'string') {
    orderDate = order.created_at.substring(0, 10);
  } else if (order.created_at instanceof Date) {
    orderDate = order.created_at.toISOString().substring(0, 10);
  } else {
    orderDate = new Date().toISOString().substring(0, 10);
  }

  const shipmentData = {
    order_id: order.order_number,
    order_date: orderDate,
    pickup_location: 'Primary',
    billing_customer_name: fullName,
    billing_first_name: firstName,
    billing_last_name: lastName,
    billing_address: order.shipping_address,
    billing_city: order.shipping_city,
    billing_pincode: String(order.shipping_pincode),
    billing_state: order.shipping_state,
    billing_country: 'India',
    billing_email: order.customer_email,
    billing_phone: String(order.customer_phone),
    shipping_is_billing: true,
    order_items: order.items.map((item) => ({
      name: item.product_name,
      sku: String(item.product_id),
      units: parseInt(item.quantity, 10),
      selling_price: parseFloat(item.price)
    })),
    payment_method: 'Prepaid',
    sub_total: parseFloat(order.subtotal),
    length: 10,
    breadth: 10,
    height: 10,
    weight: 0.5
  };

  // 3. Create shipment
  const shipmentResponse = await axios.post(
    'https://apiv2.shiprocket.in/v1/external/orders/create/adhoc',
    shipmentData,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      timeout: 30000
    }
  );

  if (shipmentResponse.status !== 200) {
    throw new Error(JSON.stringify(shipmentResponse.data));
  }

  const shipmentResult = shipmentResponse.data;

  // 4. Save Shiprocket IDs to the order
  await db.collection('orders').updateOne(
    { id: order.id },
    {
      $set: {
        shiprocket_order_id: String(shipmentResult.order_id || ''),
        tracking_id: String(shipmentResult.shipment_id || ''),
        updated_at: new Date().toISOString()
      }
    }
  );

  return shipmentResult;
}

module.exports = {
  createShiprocketShipment,
  SHIPROCKET_EMAIL,
  SHIPROCKET_PASSWORD
};
