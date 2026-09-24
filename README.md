# Sellx

Sellx is a full-stack ecommerce marketplace for buyers, service providers, and dispatch riders.

## Included

- Responsive animated storefront
- Buyer, provider, and rider role-based JWT authentication
- Product search and provider product publishing API
- Local cart with checkout and order dashboard
- Paystack transaction initialization, verification, and signed webhook handling
- Provider order status updates
- Rider delivery status updates
- Server-side validation, password hashing, rate limiting, and protected routes

## Run locally

Requires Node.js 18+ and MongoDB.

```bash
npm install
cp .env.example .env
npm run dev
```

Open `http://localhost:5000`.

Set these values in `.env`:

```env
PORT=5000
MONGO_URI=mongodb://127.0.0.1:27017/sellx
JWT_SECRET=use-a-long-random-secret
PAYSTACK_SECRET_KEY=sk_test_your_key
FRONTEND_URL=http://localhost:5000
```

Configure the Paystack webhook URL as:

`https://your-domain.example/api/payments/webhook`

Use Paystack test keys in development. The secret key must remain server-side. The checkout currently creates one order per first cart item; multi-item cart support should use an order-items collection before production launch.
