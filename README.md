# Sellx

Sellx is a full-stack ecommerce platform for buyers, service providers, and dispatch riders.

## Features

- Role-based registration and login with JWT
- Product publishing for service providers
- Buyer cart and order checkout
- Paystack payment initialization and verification
- Payment webhook support
- Provider order management
- Rider delivery dashboard
- Responsive animated frontend served by Express

## Run locally

1. Install Node.js 18+ and MongoDB.
2. Copy `.env.example` to `.env` and fill in the values.
3. Run `npm install`.
4. Run `npm run dev`.
5. Open `http://localhost:5000`.

Use Paystack test keys during development. Never expose `PAYSTACK_SECRET_KEY` in frontend code.
