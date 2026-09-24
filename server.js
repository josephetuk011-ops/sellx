import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import mongoose from 'mongoose';
import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import validator from 'validator';

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET is required');

app.use(cors({ origin: process.env.FRONTEND_URL || true }));
app.use(express.json({ limit: '1mb' }));
app.use(morgan('tiny'));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 100 }));

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true, minlength: 6 },
  role: { type: String, enum: ['buyer', 'provider', 'rider'], required: true }
}, { timestamps: true });
userSchema.pre('save', async function(next) { if (!this.isModified('password')) return next(); this.password = await bcrypt.hash(this.password, 12); next(); });
userSchema.methods.public = function() { return { id: this._id, name: this.name, email: this.email, role: this.role }; };
const User = mongoose.model('User', userSchema);

const productSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true }, description: String,
  price: { type: Number, required: true, min: 0 }, category: String,
  stock: { type: Number, default: 1, min: 0 }, imageUrl: String,
  seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
}, { timestamps: true });
const Product = mongoose.model('Product', productSchema);

const orderSchema = new mongoose.Schema({
  buyer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  provider: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  quantity: { type: Number, min: 1, required: true }, totalAmount: Number,
  shippingAddress: { type: String, required: true }, paymentReference: { type: String, unique: true, sparse: true },
  paymentStatus: { type: String, enum: ['pending', 'paid', 'failed'], default: 'pending' },
  status: { type: String, enum: ['pending', 'processing', 'out_for_delivery', 'delivered', 'cancelled'], default: 'pending' }
}, { timestamps: true });
const Order = mongoose.model('Order', orderSchema);

const deliverySchema = new mongoose.Schema({
  order: { type: mongoose.Schema.Types.ObjectId, ref: 'Order', required: true },
  rider: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  pickupLocation: String, dropoffLocation: String, fare: Number,
  status: { type: String, enum: ['assigned', 'picked_up', 'in_transit', 'delivered'], default: 'assigned' }
}, { timestamps: true });
const Delivery = mongoose.model('Delivery', deliverySchema);

function tokenFor(user) { return jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '7d' }); }
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return res.status(401).json({ message: 'Authentication required' });
  try { req.user = jwt.verify(header.slice(7), JWT_SECRET); next(); } catch { res.status(401).json({ message: 'Invalid or expired token' }); }
}
function roles(...allowed) { return (req, res, next) => allowed.includes(req.user.role) ? next() : res.status(403).json({ message: 'Insufficient permissions' }); }
async function currentUser(req) { return User.findById(req.user.id); }

app.get('/api/health', (_, res) => res.json({ ok: true, service: 'Sellx API' }));
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !validator.isEmail(email || '') || !password || password.length < 6 || !['buyer', 'provider', 'rider'].includes(role)) return res.status(400).json({ message: 'Valid name, email, password, and role are required' });
    if (await User.findOne({ email: email.toLowerCase() })) return res.status(409).json({ message: 'Email is already registered' });
    const user = await User.create({ name, email, password, role });
    res.status(201).json({ token: tokenFor(user), user: user.public() });
  } catch (e) { res.status(500).json({ message: 'Unable to create account' }); }
});
app.post('/api/auth/login', async (req, res) => {
  const { email, password, role } = req.body;
  const user = await User.findOne({ email: (email || '').toLowerCase() });
  if (!user || !(await bcrypt.compare(password || '', user.password)) || (role && role !== user.role)) return res.status(401).json({ message: 'Invalid login details' });
  res.json({ token: tokenFor(user), user: user.public() });
});
app.get('/api/auth/me', auth, async (req, res) => { const user = await currentUser(req); res.json({ user: user?.public() }); });

app.get('/api/products', async (req, res) => { const query = req.query.search ? { name: new RegExp(req.query.search, 'i') } : {}; res.json(await Product.find(query).populate('seller', 'name').sort({ createdAt: -1 })); });
app.post('/api/products', auth, roles('provider'), async (req, res) => { const { name, description, price, category, stock, imageUrl } = req.body; if (!name || Number(price) < 0) return res.status(400).json({ message: 'Product name and valid price are required' }); const product = await Product.create({ name, description, price, category, stock, imageUrl, seller: req.user.id }); res.status(201).json(product); });

app.post('/api/orders', auth, roles('buyer'), async (req, res) => {
  const { productId, quantity = 1, shippingAddress } = req.body;
  const product = await Product.findById(productId);
  if (!product || product.stock < quantity || !shippingAddress) return res.status(400).json({ message: 'Product, stock, quantity, and address are required' });
  const order = await Order.create({ buyer: req.user.id, provider: product.seller, product: product._id, quantity, totalAmount: product.price * quantity, shippingAddress });
  const reference = `SX-${order._id}-${Date.now()}`; order.paymentReference = reference; await order.save();
  try {
    const response = await fetch('https://api.paystack.co/transaction/initialize', { method: 'POST', headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ email: (await currentUser(req)).email, amount: Math.round(order.totalAmount * 100), reference, callback_url: `${process.env.FRONTEND_URL}/?payment=callback` }) });
    const data = await response.json(); if (!data.status) throw new Error('Paystack initialization failed');
    res.status(201).json({ order, authorizationUrl: data.data.authorization_url, reference });
  } catch (e) { await Order.findByIdAndDelete(order._id); res.status(502).json({ message: 'Payment gateway unavailable' }); }
});
app.get('/api/payments/verify/:reference', auth, async (req, res) => {
  const response = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(req.params.reference)}`, { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } });
  const data = await response.json(); const order = await Order.findOne({ paymentReference: req.params.reference });
  if (!order || String(order.buyer) !== req.user.id) return res.status(404).json({ message: 'Order not found' });
  if (data.status && data.data?.status === 'success') { order.paymentStatus = 'paid'; order.status = 'processing'; await order.save(); await Product.findByIdAndUpdate(order.product, { $inc: { stock: -order.quantity } }); }
  res.json({ paid: order.paymentStatus === 'paid', order });
});
app.post('/api/payments/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const signature = crypto.createHmac('sha512', process.env.PAYSTACK_SECRET_KEY).update(req.body).digest('hex');
  if (signature !== req.headers['x-paystack-signature']) return res.sendStatus(401);
  const event = JSON.parse(req.body.toString()); if (event.event === 'charge.success') { const order = await Order.findOne({ paymentReference: event.data.reference }); if (order && order.paymentStatus !== 'paid') { order.paymentStatus = 'paid'; order.status = 'processing'; await order.save(); await Product.findByIdAndUpdate(order.product, { $inc: { stock: -order.quantity } }); } }
  res.sendStatus(200);
});

app.get('/api/dashboard', auth, async (req, res) => {
  if (req.user.role === 'buyer') return res.json({ orders: await Order.find({ buyer: req.user.id }).populate('product') });
  if (req.user.role === 'provider') return res.json({ products: await Product.find({ seller: req.user.id }), orders: await Order.find({ provider: req.user.id }).populate('product buyer', 'name email') });
  res.json({ deliveries: await Delivery.find({ rider: req.user.id }).populate({ path: 'order', populate: { path: 'product buyer', select: 'name email price' } }) });
});
app.patch('/api/orders/:id/status', auth, roles('provider'), async (req, res) => { const order = await Order.findOneAndUpdate({ _id: req.params.id, provider: req.user.id }, { status: req.body.status }, { new: true }); if (!order) return res.status(404).json({ message: 'Order not found' }); res.json(order); });
app.post('/api/deliveries', auth, roles('rider'), async (req, res) => { const delivery = await Delivery.create({ ...req.body, rider: req.user.id }); await Order.findByIdAndUpdate(req.body.order, { status: 'out_for_delivery' }); res.status(201).json(delivery); });
app.patch('/api/deliveries/:id/status', auth, roles('rider'), async (req, res) => { const delivery = await Delivery.findOneAndUpdate({ _id: req.params.id, rider: req.user.id }, { status: req.body.status }, { new: true }); if (!delivery) return res.status(404).json({ message: 'Delivery not found' }); if (req.body.status === 'delivered') await Order.findByIdAndUpdate(delivery.order, { status: 'delivered' }); res.json(delivery); });

app.use(express.static('public'));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ message: 'Unexpected server error' }); });
mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/sellx').then(() => app.listen(PORT, () => console.log(`Sellx running at http://localhost:${PORT}`))).catch(err => { console.error(err); process.exit(1); });
