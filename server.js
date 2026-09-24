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
const PORT = Number(process.env.PORT || 5000);
const JWT_SECRET = process.env.JWT_SECRET;
const ROLES = ['buyer', 'provider', 'rider'];
if (!JWT_SECRET) throw new Error('JWT_SECRET is required');

app.use(cors({ origin: process.env.FRONTEND_URL || true }));
app.use(morgan('tiny'));
app.post('/api/payments/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const signature = crypto.createHmac('sha512', process.env.PAYSTACK_SECRET_KEY || '').update(req.body).digest('hex');
    if (!process.env.PAYSTACK_SECRET_KEY || signature !== req.headers['x-paystack-signature']) return res.sendStatus(401);
    const event = JSON.parse(req.body.toString());
    if (event.event === 'charge.success') await markOrderPaid(event.data.reference);
    return res.sendStatus(200);
  } catch (error) { console.error('Paystack webhook:', error.message); return res.sendStatus(400); }
});
app.use(express.json({ limit: '1mb' }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 100 }));

const userSchema = new mongoose.Schema({ name: { type: String, required: true, trim: true }, email: { type: String, required: true, unique: true, lowercase: true, trim: true }, password: { type: String, required: true, minlength: 6 }, role: { type: String, enum: ROLES, required: true } }, { timestamps: true });
userSchema.pre('save', async function(next) { if (!this.isModified('password')) return next(); this.password = await bcrypt.hash(this.password, 12); next(); });
userSchema.methods.public = function() { return { id: this._id, name: this.name, email: this.email, role: this.role }; };
const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', new mongoose.Schema({ name: { type: String, required: true, trim: true }, description: String, price: { type: Number, required: true, min: 0 }, category: String, stock: { type: Number, default: 1, min: 0 }, imageUrl: String, seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true } }, { timestamps: true }));
const Order = mongoose.model('Order', new mongoose.Schema({ buyer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, provider: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true }, quantity: { type: Number, min: 1, required: true }, totalAmount: { type: Number, required: true }, shippingAddress: { type: String, required: true }, paymentReference: { type: String, unique: true, sparse: true }, paymentStatus: { type: String, enum: ['pending', 'paid', 'failed'], default: 'pending' }, status: { type: String, enum: ['pending', 'processing', 'out_for_delivery', 'delivered', 'cancelled'], default: 'pending' } }, { timestamps: true }));
const Delivery = mongoose.model('Delivery', new mongoose.Schema({ order: { type: mongoose.Schema.Types.ObjectId, ref: 'Order', required: true }, rider: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, pickupLocation: String, dropoffLocation: String, fare: { type: Number, min: 0 }, status: { type: String, enum: ['assigned', 'picked_up', 'in_transit', 'delivered'], default: 'assigned' } }, { timestamps: true }));

const tokenFor = user => jwt.sign({ id: String(user._id), role: user.role }, JWT_SECRET, { expiresIn: '7d' });
function auth(req, res, next) { const value = req.headers.authorization || ''; if (!value.startsWith('Bearer ')) return res.status(401).json({ message: 'Authentication required' }); try { req.user = jwt.verify(value.slice(7), JWT_SECRET); next(); } catch { return res.status(401).json({ message: 'Invalid or expired token' }); } }
const roles = (...allowed) => (req, res, next) => allowed.includes(req.user.role) ? next() : res.status(403).json({ message: 'Insufficient permissions' });
const safe = value => String(value || '').trim();

app.get('/api/health', (_, res) => res.json({ ok: true, service: 'Sellx API' }));
app.post('/api/auth/register', async (req, res) => { try { const { name, email, password, role } = req.body; const normalized = safe(email).toLowerCase(); if (!safe(name) || !validator.isEmail(normalized) || !password || password.length < 6 || !ROLES.includes(role)) return res.status(400).json({ message: 'Valid name, email, password, and role are required' }); if (await User.exists({ email: normalized })) return res.status(409).json({ message: 'Email is already registered' }); const user = await User.create({ name: safe(name), email: normalized, password, role }); res.status(201).json({ token: tokenFor(user), user: user.public() }); } catch (error) { res.status(500).json({ message: 'Unable to create account' }); } });
app.post('/api/auth/login', async (req, res) => { const email = safe(req.body.email).toLowerCase(); const user = await User.findOne({ email }); if (!user || !(await bcrypt.compare(req.body.password || '', user.password)) || (req.body.role && req.body.role !== user.role)) return res.status(401).json({ message: 'Invalid login details' }); res.json({ token: tokenFor(user), user: user.public() }); });
app.get('/api/auth/me', auth, async (req, res) => { const user = await User.findById(req.user.id); if (!user) return res.status(404).json({ message: 'User not found' }); res.json({ user: user.public() }); });

app.get('/api/products', async (req, res) => { const search = safe(req.query.search); const query = search ? { $or: [{ name: new RegExp(search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i') }, { category: new RegExp(search, 'i') }] } : {}; res.json(await Product.find(query).populate('seller', 'name').sort({ createdAt: -1 })); });
app.post('/api/products', auth, roles('provider'), async (req, res) => { const { name, description, price, category, stock, imageUrl } = req.body; if (!safe(name) || !Number.isFinite(Number(price)) || Number(price) < 0) return res.status(400).json({ message: 'Product name and valid price are required' }); res.status(201).json(await Product.create({ name: safe(name), description: safe(description), price: Number(price), category: safe(category), stock: Math.max(0, Number(stock ?? 1)), imageUrl: safe(imageUrl), seller: req.user.id })); });

async function markOrderPaid(reference) { const order = await Order.findOne({ paymentReference: reference }); if (!order || order.paymentStatus === 'paid') return order; const product = await Product.findById(order.product); if (!product || product.stock < order.quantity) return order; order.paymentStatus = 'paid'; order.status = 'processing'; await order.save(); await Product.findByIdAndUpdate(product._id, { $inc: { stock: -order.quantity } }); return order; }
app.post('/api/orders', auth, roles('buyer'), async (req, res) => { const product = await Product.findById(req.body.productId); const quantity = Number(req.body.quantity || 1); const address = safe(req.body.shippingAddress); if (!product || !Number.isInteger(quantity) || quantity < 1 || product.stock < quantity || !address) return res.status(400).json({ message: 'Product, available quantity, and shipping address are required' }); if (!process.env.PAYSTACK_SECRET_KEY) return res.status(503).json({ message: 'Payment gateway is not configured' }); const user = await User.findById(req.user.id); const order = await Order.create({ buyer: user._id, provider: product.seller, product: product._id, quantity, totalAmount: product.price * quantity, shippingAddress: address, paymentReference: `SX-${Date.now()}-${crypto.randomBytes(4).toString('hex')}` }); try { const response = await fetch('https://api.paystack.co/transaction/initialize', { method: 'POST', headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ email: user.email, amount: Math.round(order.totalAmount * 100), reference: order.paymentReference, callback_url: `${process.env.FRONTEND_URL || ''}/?payment=callback` }) }); const data = await response.json(); if (!response.ok || !data.status) throw new Error('Paystack initialization failed'); res.status(201).json({ order, authorizationUrl: data.data.authorization_url, reference: order.paymentReference }); } catch { await Order.findByIdAndDelete(order._id); res.status(502).json({ message: 'Payment gateway unavailable' }); } });
app.get('/api/payments/verify/:reference', auth, roles('buyer'), async (req, res) => { const order = await Order.findOne({ paymentReference: req.params.reference, buyer: req.user.id }); if (!order) return res.status(404).json({ message: 'Order not found' }); const response = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(order.paymentReference)}`, { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } }); const data = await response.json(); if (data.status && data.data?.status === 'success') await markOrderPaid(order.paymentReference); res.json({ paid: (await Order.findById(order._id)).paymentStatus === 'paid', order: await Order.findById(order._id).populate('product') }); });

app.get('/api/dashboard', auth, async (req, res) => { if (req.user.role === 'buyer') return res.json({ orders: await Order.find({ buyer: req.user.id }).populate('product provider', 'name price imageUrl') }); if (req.user.role === 'provider') return res.json({ products: await Product.find({ seller: req.user.id }), orders: await Order.find({ provider: req.user.id }).populate('product buyer', 'name email price') }); return res.json({ deliveries: await Delivery.find({ rider: req.user.id }).populate({ path: 'order', populate: { path: 'product buyer', select: 'name email price' } }) }); });
app.patch('/api/orders/:id/status', auth, roles('provider'), async (req, res) => { if (!['processing', 'out_for_delivery', 'cancelled'].includes(req.body.status)) return res.status(400).json({ message: 'Invalid order status' }); const order = await Order.findOneAndUpdate({ _id: req.params.id, provider: req.user.id }, { status: req.body.status }, { new: true }); if (!order) return res.status(404).json({ message: 'Order not found' }); res.json(order); });
app.post('/api/deliveries', auth, roles('rider'), async (req, res) => { const order = await Order.findById(req.body.order); if (!order || order.paymentStatus !== 'paid') return res.status(400).json({ message: 'Only paid orders can be assigned' }); const delivery = await Delivery.create({ order: order._id, rider: req.user.id, pickupLocation: safe(req.body.pickupLocation), dropoffLocation: safe(req.body.dropoffLocation), fare: Number(req.body.fare || 0) }); order.status = 'out_for_delivery'; await order.save(); res.status(201).json(delivery); });
app.patch('/api/deliveries/:id/status', auth, roles('rider'), async (req, res) => { if (!['assigned', 'picked_up', 'in_transit', 'delivered'].includes(req.body.status)) return res.status(400).json({ message: 'Invalid delivery status' }); const delivery = await Delivery.findOneAndUpdate({ _id: req.params.id, rider: req.user.id }, { status: req.body.status }, { new: true }); if (!delivery) return res.status(404).json({ message: 'Delivery not found' }); if (req.body.status === 'delivered') await Order.findByIdAndUpdate(delivery.order, { status: 'delivered' }); res.json(delivery); });

app.use(express.static('public'));
app.use((error, req, res, next) => { console.error(error); res.status(500).json({ message: 'Unexpected server error' }); });
mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/sellx').then(() => app.listen(PORT, () => console.log(`Sellx running at http://localhost:${PORT}`))).catch(error => { console.error('MongoDB connection failed:', error.message); process.exit(1); });
