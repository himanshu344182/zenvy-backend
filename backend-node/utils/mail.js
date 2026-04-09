const nodemailer = require('nodemailer');

const ZOHO_ACCOUNT_EMAIL = process.env.ZOHO_ACCOUNT_EMAIL || '';
const ZOHO_CLIENT_ID = process.env.ZOHO_CLIENT_ID || '';
const ZOHO_CLIENT_SECRET = process.env.ZOHO_CLIENT_SECRET || '';
const ZOHO_REFRESH_TOKEN = process.env.ZOHO_REFRESH_TOKEN || '';

/**
 * Create Nodemailer transporter configured for Zoho Mail with OAuth2.
 * Returns null if credentials aren't set.
 */
function createTransporter() {
  if (!ZOHO_ACCOUNT_EMAIL || !ZOHO_CLIENT_ID || !ZOHO_CLIENT_SECRET || !ZOHO_REFRESH_TOKEN) {
    return null;
  }

  return nodemailer.createTransport({
    host: 'smtp.zoho.com', // Changed from .in to .com
    port: 465,
    secure: true,
    auth: {
      type: 'OAuth2',
      user: ZOHO_ACCOUNT_EMAIL,
      clientId: ZOHO_CLIENT_ID,
      clientSecret: ZOHO_CLIENT_SECRET,
      refreshToken: ZOHO_REFRESH_TOKEN,
      accessUrl: 'https://accounts.zoho.com/oauth/v2/token' // Changed from .in to .com
    },
    connectionTimeout: 10000, // 10 seconds
    greetingTimeout: 10000,
    socketTimeout: 10000
  });
}

/**
 * Send an order confirmation email to the customer.
 * Silently fails if Zoho is not configured.
 */
async function sendOrderConfirmationEmail(order) {
  const transporter = createTransporter();
  if (!transporter) {
    console.log('Zoho Mail not configured — skipping order confirmation email.');
    return;
  }

  const itemRows = order.items
    .map(
      (item) =>
        `<tr>
          <td style="padding:8px;border-bottom:1px solid #eee;">${item.product_name}</td>
          <td style="padding:8px;border-bottom:1px solid #eee;text-align:center;">${item.quantity}</td>
          <td style="padding:8px;border-bottom:1px solid #eee;text-align:right;">₹${item.price.toFixed(2)}</td>
        </tr>`
    )
    .join('');

  const html = `
    <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:600px;margin:0 auto;color:#333;">
      <div style="background:#111;color:#fff;padding:24px;text-align:center;">
        <h1 style="margin:0;font-size:24px;">Order Confirmed ✓</h1>
      </div>
      <div style="padding:24px;">
        <p>Hi <strong>${order.customer_name}</strong>,</p>
        <p>Thank you for your purchase! Your order <strong>${order.order_number}</strong> has been confirmed.</p>

        <table style="width:100%;border-collapse:collapse;margin:16px 0;">
          <thead>
            <tr style="background:#f5f5f5;">
              <th style="padding:8px;text-align:left;">Item</th>
              <th style="padding:8px;text-align:center;">Qty</th>
              <th style="padding:8px;text-align:right;">Price</th>
            </tr>
          </thead>
          <tbody>${itemRows}</tbody>
        </table>

        <div style="text-align:right;margin-top:12px;">
          <p style="margin:4px 0;">Subtotal: ₹${order.subtotal.toFixed(2)}</p>
          <p style="margin:4px 0;font-size:18px;font-weight:bold;">Total: ₹${order.total.toFixed(2)}</p>
        </div>

        <hr style="margin:20px 0;border:none;border-top:1px solid #eee;" />

        <h3 style="margin-bottom:8px;">Shipping Address</h3>
        <p style="margin:0;">${order.shipping_address}<br/>${order.shipping_city}, ${order.shipping_state} - ${order.shipping_pincode}</p>

        <p style="margin-top:20px;color:#888;font-size:13px;">
          You can track your order using order number: <strong>${order.order_number}</strong>
        </p>
      </div>
      <div style="background:#f5f5f5;padding:16px;text-align:center;font-size:12px;color:#999;">
        © ${new Date().getFullYear()} Zenvy. All rights reserved.
      </div>
    </div>
  `;

  try {
    await transporter.sendMail({
      from: `"Zenvy" <${ZOHO_ACCOUNT_EMAIL}>`,
      to: order.customer_email,
      subject: `Order Confirmed - ${order.order_number}`,
      html
    });
    console.log(`Order confirmation email sent to ${order.customer_email}`);
  } catch (err) {
    console.error('Failed to send order confirmation email:', err.message);
  }
}

/**
 * Send a shipping notification email to the customer.
 */
async function sendShippingNotificationEmail(order) {
  const transporter = createTransporter();
  if (!transporter) return;

  const html = `
    <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:600px;margin:0 auto;color:#333;">
      <div style="background:#111;color:#fff;padding:24px;text-align:center;">
        <h1 style="margin:0;font-size:24px;">Your Order Has Shipped! 🚚</h1>
      </div>
      <div style="padding:24px;">
        <p>Hi <strong>${order.customer_name}</strong>,</p>
        <p>Great news! Your order <strong>${order.order_number}</strong> has been shipped.</p>
        ${order.tracking_id ? `<p>Tracking ID: <strong>${order.tracking_id}</strong></p>` : ''}
        <p style="margin-top:20px;color:#888;font-size:13px;">
          You'll receive another email once your order is delivered.
        </p>
      </div>
      <div style="background:#f5f5f5;padding:16px;text-align:center;font-size:12px;color:#999;">
        © ${new Date().getFullYear()} Zenvy. All rights reserved.
      </div>
    </div>
  `;

  try {
    await transporter.sendMail({
      from: `"Zenvy" <${ZOHO_ACCOUNT_EMAIL}>`,
      to: order.customer_email,
      subject: `Order Shipped - ${order.order_number}`,
      html
    });
    console.log(`Shipping notification email sent to ${order.customer_email}`);
  } catch (err) {
    console.error('Failed to send shipping notification email:', err.message);
  }
}

module.exports = {
  sendOrderConfirmationEmail,
  sendShippingNotificationEmail
};
