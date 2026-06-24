/**
 * Bihar & Nepal Momo Express — Express Backend
 * Har Swad Mein Maa Ka Haath ❤️
 * High Security | MongoDB + Local JSON Fallback | Coupons Engine
 */

const express = require('express');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');

const app  = express();
const PORT = 3001;
const DB_FILE = path.join(__dirname, 'data', 'db.json');

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));
app.use(express.static(__dirname)); // serve static front-end assets

/* ─── Crypto & Security Helpers ─── */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedPassword) {
  if (!storedPassword) return false;
  // If the password in DB is not hashed yet (legacy user), we check direct equality
  if (!storedPassword.includes(':')) {
    return password === storedPassword;
  }
  const [salt, originalHash] = storedPassword.split(':');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return hash === originalHash;
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

/* ─── MongoDB & Mongoose Integration ─── */
let mongoose;
let useMongo = false;

// Attempt to load Mongoose dynamically
try {
  mongoose = require('mongoose');
} catch (err) {
  console.warn("⚠️ Mongoose module not found. Force falling back to local JSON file DB.");
}

const MONGO_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/momo_express';

// Define MongoDB Schemas and Models
let Customer, Menu, Order, Coupon, AdminSettings, Subscription;

function initMongoModels() {
  const customerSchema = new mongoose.Schema({
    phone: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    password: { type: String, required: true }, // secure PBKDF2 hash
    address: { type: String, default: '' },
    pincode: { type: String, default: '' },
    landmark: { type: String, default: '' },
    sessionToken: { type: String, default: '' }
  });
  Customer = mongoose.model('Customer', customerSchema);

  const variantSchema = new mongoose.Schema({
    id: { type: String, required: true },
    label: { type: String, required: true },
    price: { type: Number, required: true },
    cost: { type: Number, required: true },
    stock: { type: Number, default: 100 },
    discount: { type: Number, default: 0 }
  });

  const menuSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    cat: { type: String, required: true },
    name: { type: String, required: true },
    emoji: { type: String, default: '' },
    desc: { type: String, default: '' },
    veg: { type: Boolean, default: true },
    image: { type: String, default: 'product_default.jpg' },
    variants: [variantSchema]
  });
  Menu = mongoose.model('Menu', menuSchema);

  const orderItemSchema = new mongoose.Schema({
    itemId: { type: String, required: true },
    variantId: { type: String, required: true },
    name: { type: String, required: true },
    variant: { type: String, required: true },
    price: { type: Number, required: true },
    originalPrice: { type: Number, required: true },
    cost: { type: Number, default: 0 },
    discount: { type: Number, default: 0 },
    emoji: { type: String, default: '' },
    qty: { type: Number, required: true }
  });

  const orderSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    customer: {
      name: { type: String, required: true },
      phone: { type: String, required: true },
      address: { type: String, required: true },
      landmark: { type: String, default: '' }
    },
    items: [orderItemSchema],
    pincode: { type: String, required: true },
    zone: { type: String, required: true },
    zoneLabel: { type: String, required: true },
    subtotal: { type: Number, required: true },
    coupon: {
      code: { type: String },
      discount: { type: Number }
    },
    deliveryCharge: { type: Number, default: 0 },
    total: { type: Number, required: true },
    paymentTerm: { type: String, default: 'full' },
    paidAmount: { type: Number },
    balanceAmount: { type: Number },
    note: { type: String, default: '' },
    status: { type: String, default: 'pending' },
    statusHistory: [{
      status: { type: String },
      time: { type: String, default: () => new Date().toISOString() }
    }],
    timestamp: { type: String, default: () => new Date().toISOString() }
  });
  Order = mongoose.model('Order', orderSchema);

  const couponSchema = new mongoose.Schema({
    code: { type: String, required: true, unique: true, uppercase: true },
    type: { type: String, enum: ['flat', 'percentage'], default: 'flat' },
    value: { type: Number, required: true },
    minOrder: { type: Number, default: 0 },
    isActive: { type: Boolean, default: true },
    desc: { type: String, default: '' }
  });
  Coupon = mongoose.model('Coupon', couponSchema);

  const adminSettingsSchema = new mongoose.Schema({
    key: { type: String, default: 'adminPass' },
    val: { type: String, default: 'momo@admin2025' }
  });
  AdminSettings = mongoose.model('AdminSettings', adminSettingsSchema);

  const subscriptionSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    orderId: { type: String, required: true },
    customer: {
      name: { type: String, required: true },
      phone: { type: String, required: true },
      address: { type: String, required: true },
      landmark: { type: String, default: '' }
    },
    item: {
      itemId: { type: String, required: true },
      variantId: { type: String, required: true },
      name: { type: String, required: true },
      variant: { type: String, required: true },
      price: { type: Number, required: true },
      qty: { type: Number, required: true }
    },
    status: { type: String, default: 'active' }, // active, paused, stopped
    deliverySlot: { type: String, required: true }, // Morning (11:00 AM), Night (8:30 PM), Both (11:00 AM & 8:30 PM)
    notes: { type: String, default: '' },
    startDate: { type: String, default: () => new Date().toISOString() },
    endDate: { type: String },
    durationDays: { type: Number, default: 30 },
    price: { type: Number },
    discount: { type: Number, default: 0 },
    total: { type: Number },
    paymentTerm: { type: String, default: 'full' }, // full or split
    paidAmount: { type: Number, default: 0 },
    balanceAmount: { type: Number, default: 0 },
    deliveries: [{
      date: { type: String },
      time: { type: String },
      status: { type: String, default: 'delivered' }
    }],
    history: [{
      status: { type: String },
      time: { type: String, default: () => new Date().toISOString() }
    }],
    pauseStartDate: { type: String, default: '' },
    pauseEndDate: { type: String, default: '' }
  });
  Subscription = mongoose.model('Subscription', subscriptionSchema);
}

// Default Menu Items
const DEFAULT_MENU = [
  { id:'k1', cat:'kachori', name:'Sattu Kachori + Chutney', emoji:'', desc:'Crispy kachori filled with spiced sattu, served with hari chutney & imli chutney', veg: true, image: 'sattu_kachori_chutney.jpg', variants:[{id:'k1a',label:'2 Pcs',price:49,cost:20,stock:100,discount:0},{id:'k1b',label:'4 Pcs',price:89,cost:35,stock:100,discount:0},{id:'k1c',label:'6 Pcs',price:129,cost:50,stock:100,discount:0}] },
  { id:'k2', cat:'kachori', name:'Kachori + Aloo Sabzi + Chutney', emoji:'', desc:'Sattu kachori with spicy aloo sabzi & fresh chutney — authentic Bihar combo', veg: true, image: 'kachori_aloo_sabzi_chutney.jpg', variants:[{id:'k2a',label:'4 Pcs + Sabzi',price:119,cost:50,stock:100,discount:0},{id:'k2b',label:'6 Pcs + Sabzi',price:159,cost:70,stock:100,discount:0}] },
  { id:'s1', cat:'samosa', name:'Desi Bihari Samosa', emoji:'', desc:'Crispy homemade samosas with spiced potato filling, served with chutney', veg: true, image: 'desi_bihari_samosa.jpg', variants:[{id:'s1a',label:'2 Pcs',price:39,cost:15,stock:120,discount:0},{id:'s1b',label:'4 Pcs',price:69,cost:25,stock:120,discount:0},{id:'s1c',label:'6 Pcs',price:99,cost:40,stock:120,discount:0}] },
  { id:'l1', cat:'litti', name:'Oil Litti Chokha', emoji:'', desc:'Roasted sattu-filled litti with smoky baingan chokha — traditional Bihari style', veg: true, image: 'oil_litti_chokha.jpg', variants:[{id:'l1a',label:'Half Plate (2 Litti)',price:79,cost:30,stock:80,discount:0},{id:'l1b',label:'Full Plate (4 Litti)',price:149,cost:55,stock:80,discount:0}] },
  { id:'l2', cat:'litti', name:'Ghee Litti Chokha', emoji:'', desc:'Premium pure ghee coated litti with smoky chokha — rich & aromatic', veg: true, image: 'ghee_litti_chokha.jpg', variants:[{id:'l2a',label:'Half Plate (2 Litti)',price:99,cost:40,stock:80,discount:0},{id:'l2b',label:'Full Plate (4 Litti)',price:179,cost:70,stock:80,discount:0}] },
  { id:'l3', cat:'litti', name:'Butter Litti Chokha', emoji:'', desc:'Buttery soft litti with creamy chokha — indulgent Bihari delicacy', veg: true, image: 'butter_litti_chokha.jpg', variants:[{id:'l3a',label:'Half Plate (2 Litti)',price:109,cost:45,stock:85,discount:0},{id:'l3b',label:'Full Plate (4 Litti)',price:199,cost:80,stock:85,discount:0}] },
  { id:'m1', cat:'momos', name:'Veg Steamed Momos', emoji:'', desc:'Classic Nepali steamed momos filled with spiced veggies, served with red chutney', veg: true, image: 'veg_steamed_momos.jpg', variants:[{id:'m1a',label:'5 Pcs',price:69,cost:25,stock:150,discount:0},{id:'m1b',label:'10 Pcs',price:129,cost:45,stock:150,discount:0}] },
  { id:'m2', cat:'momos', name:'Paneer Momos', emoji:'', desc:'Juicy paneer-filled Nepali momos with aromatic spices & fiery red chutney', veg: true, image: 'paneer_momos.jpg', variants:[{id:'m2a',label:'5 Pcs',price:89,cost:35,stock:150,discount:0},{id:'m2b',label:'10 Pcs',price:169,cost:65,stock:150,discount:0}] },
  { id:'m3', cat:'momos', name:'Fried Momos', emoji:'', desc:'Golden crispy fried momos — crunchy outside, soft inside, served with chutney', veg: true, image: 'fried_momos.jpg', variants:[{id:'m3a',label:'5 Pcs',price:79,cost:30,stock:120,discount:0},{id:'m3b',label:'10 Pcs',price:149,cost:55,stock:120,discount:0}] },
  { id:'m4', cat:'momos', name:'Kurkure Momos', emoji:'', desc:'Extra crispy coated momos — a crowd favourite! Served with spicy chutney', veg: true, image: 'kurkure_momos.jpg', variants:[{id:'m4a',label:'5 Pcs',price:99,cost:40,stock:120,discount:0},{id:'m4b',label:'10 Pcs',price:189,cost:75,stock:120,discount:0}] },
  { id:'t1', cat:'tiffin', name:'Daily Veg Tiffin', emoji:'', desc:'4 Roti + Sabzi + Dal + Rice + Salad — wholesome homestyle meal', veg: true, image: 'daily_veg_tiffin.jpg', variants:[{id:'t1a',label:'Per Meal',price:79,cost:35,stock:60,discount:0}] },
  { id:'t2', cat:'tiffin', name:'Monthly Lunch Tiffin', emoji:'', desc:'Wholesome homestyle lunch delivered daily — advance booking required', veg: true, image: 'monthly_lunch_tiffin.jpg', variants:[{id:'t2a',label:'Per Month',price:2199,cost:1100,stock:50,discount:100}] },
  { id:'t3', cat:'tiffin', name:'Monthly Dinner Tiffin', emoji:'', desc:'Wholesome homestyle dinner delivered daily — advance booking required', veg: true, image: 'monthly_dinner_tiffin.jpg', variants:[{id:'t3a',label:'Per Month',price:2199,cost:1100,stock:50,discount:100}] },
  { id:'t4', cat:'tiffin', name:'Monthly Lunch + Dinner', emoji:'', desc:'Complete meal plan — both lunch & dinner daily. Best value!', veg: true, image: 'monthly_lunch_dinner.jpg', variants:[{id:'t4a',label:'Per Month',price:3999,cost:2000,stock:50,discount:200}] },
  { id:'c1', cat:'combo', name:'Combo 1 — Kachori Special', emoji:'', desc:'4 Sattu Kachori + Aloo Sabzi + Cold Drink — value saver!', veg: true, image: 'combo_1_kachori_special.jpg', variants:[{id:'c1a',label:'Full Combo',price:149,cost:60,stock:70,discount:10}] },
  { id:'c2', cat:'combo', name:'Combo 2 — Momo Blast', emoji:'', desc:'10 Veg Momos + Cold Drink — bestseller combo!', veg: true, image: 'combo_2_momo_blast.jpg', variants:[{id:'c2a',label:'Full Combo',price:159,cost:65,stock:70,discount:10}] },
  { id:'c3', cat:'combo', name:'Combo 3 — Litti Special', emoji:'', desc:'Full Plate Ghee Litti Chokha + Cold Drink', veg: true, image: 'combo_3_litti_special.jpg', variants:[{id:'c3a',label:'Full Combo',price:199,cost:85,stock:70,discount:15}] },
  { id:'c4', cat:'combo', name:'Family Pack', emoji:'', desc:'8 Litti + Chokha + 10 Veg Momos — perfect for the whole family!', veg: true, image: 'family_pack.jpg', variants:[{id:'c4a',label:'Family Pack',price:349,cost:150,stock:40,discount:30}] }
];

/* ─── Local JSON DB Fallback Functions ─── */
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'));
}

function readDB() {
  try {
    const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
    if (!data.orders) data.orders = [];
    if (!data.menu) {
      data.menu = DEFAULT_MENU;
    } else {
      // Migrate existing menu items' image paths if they are still the default placeholder
      let migrated = false;
      data.menu.forEach(item => {
        if (item.image === 'product_default.jpg') {
          const defaultItem = DEFAULT_MENU.find(m => m.id === item.id);
          if (defaultItem) {
            item.image = defaultItem.image;
            migrated = true;
          }
        }
      });
      if (migrated) {
        fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
      }
    }
    if (!data.customers) data.customers = [];
    if (!data.coupons) data.coupons = [];
    if (!data.subscriptions) data.subscriptions = [];
    if (!data.adminPass) data.adminPass = hashPassword('momo@admin2025');
    // Upgrade admin password if it's plaintext
    if (data.adminPass && !data.adminPass.includes(':')) {
      data.adminPass = hashPassword(data.adminPass);
      fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
    }
    return data;
  } catch {
    const defaultData = {
      orders: [],
      menu: DEFAULT_MENU,
      customers: [],
      coupons: [],
      subscriptions: [],
      adminPass: hashPassword('momo@admin2025')
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(defaultData, null, 2));
    return defaultData;
  }
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// Database Abstraction Adapter
const dbAdapter = {
  // Customers
  async findCustomer(phone) {
    if (useMongo) {
      return await Customer.findOne({ phone: phone.trim() });
    } else {
      const db = readDB();
      return db.customers.find(c => c.phone === phone.trim());
    }
  },
  async createCustomer(customerData) {
    if (useMongo) {
      const c = new Customer(customerData);
      return await c.save();
    } else {
      const db = readDB();
      db.customers.push(customerData);
      writeDB(db);
      return customerData;
    }
  },
  async updateCustomerProfile(phone, updateData) {
    if (useMongo) {
      return await Customer.findOneAndUpdate({ phone: phone.trim() }, { $set: updateData }, { new: true });
    } else {
      const db = readDB();
      const c = db.customers.find(x => x.phone === phone.trim());
      if (c) {
        Object.assign(c, updateData);
        writeDB(db);
      }
      return c;
    }
  },
  async saveCustomerSession(phone, sessionToken) {
    if (useMongo) {
      await Customer.updateOne({ phone: phone.trim() }, { $set: { sessionToken } });
    } else {
      const db = readDB();
      const c = db.customers.find(x => x.phone === phone.trim());
      if (c) {
        c.sessionToken = sessionToken;
        writeDB(db);
      }
    }
  },

  // Menu
  async getMenu() {
    if (useMongo) {
      return await Menu.find({});
    } else {
      const db = readDB();
      return db.menu;
    }
  },
  async saveMenuItem(item) {
    if (useMongo) {
      return await Menu.findOneAndUpdate(
        { id: item.id },
        { $set: item },
        { upsert: true, new: true }
      );
    } else {
      const db = readDB();
      const idx = db.menu.findIndex(m => m.id === item.id);
      if (idx >= 0) db.menu[idx] = item;
      else db.menu.push(item);
      writeDB(db);
      return item;
    }
  },
  async deleteMenuItem(id) {
    if (useMongo) {
      return await Menu.deleteOne({ id });
    } else {
      const db = readDB();
      const exists = db.menu.some(m => m.id === id);
      if (!exists) return false;
      db.menu = db.menu.filter(m => m.id !== id);
      writeDB(db);
      return true;
    }
  },

  // Orders
  async getOrders(phone) {
    if (useMongo) {
      const q = phone ? { "customer.phone": phone.trim() } : {};
      return await Order.find(q);
    } else {
      const db = readDB();
      if (phone) {
        return db.orders.filter(o => o.customer.phone === phone.trim());
      }
      return db.orders;
    }
  },
  async getOrderById(id) {
    if (useMongo) {
      return await Order.findOne({ id });
    } else {
      const db = readDB();
      return db.orders.find(o => o.id === id);
    }
  },
  async saveOrder(order) {
    if (useMongo) {
      const o = new Order(order);
      return await o.save();
    } else {
      const db = readDB();
      db.orders.push(order);
      writeDB(db);
      return order;
    }
  },
  async updateOrderStatus(id, status, rejectReason) {
    if (useMongo) {
      const order = await Order.findOne({ id });
      if (!order) return null;
      order.status = status;
      order.statusHistory.push({ status, time: new Date().toISOString() });
      if (status === 'rejected' && rejectReason) order.rejectReason = rejectReason;
      await order.save();
      return order;
    } else {
      const db = readDB();
      const order = db.orders.find(o => o.id === id);
      if (!order) return null;
      order.status = status;
      order.statusHistory.push({ status, time: new Date().toISOString() });
      if (status === 'rejected' && rejectReason) order.rejectReason = rejectReason;
      writeDB(db);
      return order;
    }
  },
  async clearDeliveredOrders() {
    if (useMongo) {
      return await Order.deleteMany({ status: 'delivered' });
    } else {
      const db = readDB();
      db.orders = db.orders.filter(o => o.status !== 'delivered');
      writeDB(db);
    }
  },
  async clearAllOrders() {
    if (useMongo) {
      return await Order.deleteMany({});
    } else {
      const db = readDB();
      db.orders = [];
      writeDB(db);
    }
  },

  // Admin Settings
  async getAdminPass() {
    if (useMongo) {
      const setting = await AdminSettings.findOne({ key: 'adminPass' });
      return setting ? setting.val : hashPassword('momo@admin2025');
    } else {
      const db = readDB();
      return db.adminPass || hashPassword('momo@admin2025');
    }
  },
  async saveAdminPass(newPassHash) {
    if (useMongo) {
      await AdminSettings.updateOne(
        { key: 'adminPass' },
        { $set: { val: newPassHash } },
        { upsert: true }
      );
    } else {
      const db = readDB();
      db.adminPass = newPassHash;
      writeDB(db);
    }
  },

  // Coupons
  async getCoupons(onlyActive = false) {
    if (useMongo) {
      const q = onlyActive ? { isActive: true } : {};
      return await Coupon.find(q);
    } else {
      const db = readDB();
      if (!db.coupons) db.coupons = [];
      if (onlyActive) return db.coupons.filter(c => c.isActive);
      return db.coupons;
    }
  },
  async getCouponByCode(code) {
    const uppercaseCode = (code || '').toUpperCase().trim();
    if (useMongo) {
      return await Coupon.findOne({ code: uppercaseCode });
    } else {
      const db = readDB();
      if (!db.coupons) db.coupons = [];
      return db.coupons.find(c => c.code === uppercaseCode);
    }
  },
  async saveCoupon(couponData) {
    couponData.code = couponData.code.toUpperCase().trim();
    if (useMongo) {
      return await Coupon.findOneAndUpdate(
        { code: couponData.code },
        { $set: couponData },
        { upsert: true, new: true }
      );
    } else {
      const db = readDB();
      if (!db.coupons) db.coupons = [];
      const idx = db.coupons.findIndex(c => c.code === couponData.code);
      if (idx >= 0) db.coupons[idx] = couponData;
      else db.coupons.push(couponData);
      writeDB(db);
      return couponData;
    }
  },
  async deleteCoupon(code) {
    const uppercaseCode = (code || '').toUpperCase().trim();
    if (useMongo) {
      return await Coupon.deleteOne({ code: uppercaseCode });
    } else {
      const db = readDB();
      if (!db.coupons) db.coupons = [];
      const exists = db.coupons.some(c => c.code === uppercaseCode);
      if (!exists) return false;
      db.coupons = db.coupons.filter(c => c.code !== uppercaseCode);
      writeDB(db);
      return true;
    }
  },
  async getSubscriptions(phone) {
    if (useMongo) {
      const q = phone ? { "customer.phone": phone.trim() } : {};
      return await Subscription.find(q);
    } else {
      const db = readDB();
      if (!db.subscriptions) db.subscriptions = [];
      if (phone) {
        return db.subscriptions.filter(s => s.customer.phone === phone.trim());
      }
      return db.subscriptions;
    }
  },
  async getSubscriptionById(id) {
    if (useMongo) {
      return await Subscription.findOne({ id });
    } else {
      const db = readDB();
      if (!db.subscriptions) db.subscriptions = [];
      return db.subscriptions.find(s => s.id === id);
    }
  },
  async saveSubscription(sub) {
    if (useMongo) {
      return await Subscription.findOneAndUpdate(
        { id: sub.id },
        { $set: sub },
        { upsert: true, new: true }
      );
    } else {
      const db = readDB();
      if (!db.subscriptions) db.subscriptions = [];
      const idx = db.subscriptions.findIndex(s => s.id === sub.id);
      if (idx >= 0) db.subscriptions[idx] = sub;
      else db.subscriptions.push(sub);
      writeDB(db);
      return sub;
    }
  },
  async deleteSubscription(id) {
    if (useMongo) {
      return await Subscription.deleteOne({ id });
    } else {
      const db = readDB();
      if (!db.subscriptions) db.subscriptions = [];
      db.subscriptions = db.subscriptions.filter(s => s.id !== id);
      writeDB(db);
      return true;
    }
  }
};

// Initialize connection to MongoDB
if (mongoose) {
  console.log("Connecting to MongoDB...");
  mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 })
    .then(async () => {
      console.log("✅ MongoDB Connected successfully!");
      useMongo = true;
      initMongoModels();

      // Seed Default Menu if empty
      const menuCount = await Menu.countDocuments();
      if (menuCount === 0) {
        console.log("Seeding default menu items into MongoDB...");
        await Menu.insertMany(DEFAULT_MENU);
      } else {
        // Migrate existing default items in MongoDB if they are still product_default.jpg
        const dbItems = await Menu.find({});
        for (const item of dbItems) {
          if (item.image === 'product_default.jpg') {
            const defaultItem = DEFAULT_MENU.find(m => m.id === item.id);
            if (defaultItem) {
              item.image = defaultItem.image;
              await item.save();
            }
          }
        }
      }

      // Seed Default Admin Pass if empty
      const adminSetting = await AdminSettings.findOne({ key: 'adminPass' });
      if (!adminSetting) {
        console.log("Seeding default admin password hash into MongoDB...");
        const seedPass = new AdminSettings({ key: 'adminPass', val: hashPassword('momo@admin2025') });
        await seedPass.save();
      }
    })
    .catch(err => {
      console.warn("⚠️ MongoDB Connection Failed. Running on Local JSON File Database fallback.", err.message);
      useMongo = false;
      readDB(); // Initialize local db file
    });
} else {
  useMongo = false;
  readDB(); // Initialize local db file
}

/* ─── Security Token Middlewares ─── */
let adminSessionToken = 'ADM_SESSION_' + crypto.randomBytes(16).toString('hex'); // Generate dynamic admin session token

async function authenticateCustomer(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ success: false, error: 'Authorization token required' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, error: 'Token missing' });

  let customer;
  if (useMongo) {
    customer = await Customer.findOne({ sessionToken: token });
  } else {
    const db = readDB();
    customer = db.customers.find(c => c.sessionToken === token);
  }

  if (!customer) return res.status(401).json({ success: false, error: 'Session expired. Please log in again.' });
  req.customer = customer;
  next();
}

function authenticateAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ success: false, error: 'Authorization header missing' });
  const token = authHeader.split(' ')[1];
  if (!token || token !== adminSessionToken) {
    return res.status(401).json({ success: false, error: 'Unauthorized: Invalid admin token' });
  }
  next();
}

/* ─── Delivery Zone Logic ─── */
const BAKERY_PINCODE = '380051';
const AHMEDABAD_PREFIXES = ['380', '382', '383', '384', '385', '387', '388', '389'];
const DELIVERY_CHARGE_OTHER = 30; // ₹30 for non-380051 Ahmedabad when order < ₹149
const FREE_THRESHOLD_OTHER  = 149;
const MIN_ORDER_BAKERY  = 99;
const MIN_ORDER_OTHER   = 99;

function getDeliveryInfo(pincode, subtotal) {
  const pin = (pincode || '').trim();
  if (pin === BAKERY_PINCODE) {
    return {
      zone: 'bakery',
      label: 'Bakery City (380051)',
      minOrder: MIN_ORDER_BAKERY,
      deliveryCharge: 0,
      free: true,
      serviceable: true,
      message: '🟢 FREE Delivery! Minimum order ₹99'
    };
  }
  const prefix = pin.substring(0, 3);
  if (AHMEDABAD_PREFIXES.includes(prefix)) {
    const charge = subtotal >= FREE_THRESHOLD_OTHER ? 0 : DELIVERY_CHARGE_OTHER;
    return {
      zone: 'ahmedabad',
      label: 'Ahmedabad Area',
      minOrder: MIN_ORDER_OTHER,
      deliveryCharge: charge,
      free: charge === 0,
      serviceable: true,
      message: charge === 0
        ? `🟡 FREE Delivery! (Order ≥ ₹${FREE_THRESHOLD_OTHER})`
        : `🟡 Delivery Charge: ₹${charge} (FREE on orders ₹${FREE_THRESHOLD_OTHER}+)`
    };
  }
  return {
    zone: 'outside',
    label: 'Outside Ahmedabad',
    minOrder: null,
    deliveryCharge: null,
    free: false,
    serviceable: false,
    message: '🔴 Sorry, we only deliver within Ahmedabad'
  };
}

function validateIndianPhone(phone) {
  return /^[6-9]\d{9}$/.test((phone || '').trim());
}
function validatePincode(pin) {
  return /^\d{6}$/.test((pin || '').trim());
}

/* ══════════════════════════════════════════════
   API ROUTES
   ══════════════════════════════════════════════ */

/* ─── Health Check ─── */
app.get('/api/health', (req, res) => {
  res.json({ success: true, status: 'ok', useMongo, time: new Date().toISOString() });
});

/* ─── Delivery Info ─── */
app.post('/api/delivery-check', (req, res) => {
  const { pincode, subtotal } = req.body;
  if (!validatePincode(pincode)) {
    return res.status(400).json({ success: false, error: 'Invalid pincode (must be 6 digits)' });
  }
  res.json({ success: true, ...getDeliveryInfo(pincode, subtotal || 0) });
});

/* ─── CUSTOMER AUTHENTICATION ─── */
app.post('/api/customers/signup', async (req, res) => {
  const { phone, name, password, address, pincode, landmark } = req.body;
  if (!validateIndianPhone(phone)) {
    return res.status(400).json({ success: false, error: 'Invalid Indian mobile number' });
  }
  if (!name || name.trim().length < 2) {
    return res.status(400).json({ success: false, error: 'Name must be at least 2 characters' });
  }
  if (!password || password.length < 6) {
    return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
  }

  try {
    const exists = await dbAdapter.findCustomer(phone);
    if (exists) {
      return res.status(400).json({ success: false, error: 'Mobile number already registered' });
    }

    const token = generateSessionToken();
    const hashedPassword = hashPassword(password);
    const newCustomer = {
      phone: phone.trim(),
      name: name.trim(),
      password: hashedPassword,
      address: (address || '').trim(),
      pincode: (pincode || '').trim(),
      landmark: (landmark || '').trim(),
      sessionToken: token
    };

    await dbAdapter.createCustomer(newCustomer);
    res.status(201).json({
      success: true,
      token,
      customer: {
        phone: newCustomer.phone,
        name: newCustomer.name,
        address: newCustomer.address,
        pincode: newCustomer.pincode,
        landmark: newCustomer.landmark
      },
      message: 'Signup successful!'
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/customers/login', async (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) {
    return res.status(400).json({ success: false, error: 'Phone and password required' });
  }

  try {
    const customer = await dbAdapter.findCustomer(phone);
    if (!customer || !verifyPassword(password, customer.password)) {
      return res.status(401).json({ success: false, error: 'Invalid mobile number or password' });
    }

    const token = generateSessionToken();
    await dbAdapter.saveCustomerSession(customer.phone, token);

    res.json({
      success: true,
      token,
      customer: {
        phone: customer.phone,
        name: customer.name,
        address: customer.address,
        pincode: customer.pincode,
        landmark: customer.landmark
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put('/api/customers/profile', authenticateCustomer, async (req, res) => {
  const { name, address, pincode, landmark } = req.body;
  try {
    const updateData = {};
    if (name) updateData.name = name.trim();
    if (address) updateData.address = address.trim();
    if (pincode) updateData.pincode = pincode.trim();
    if (landmark) updateData.landmark = landmark.trim();

    const updated = await dbAdapter.updateCustomerProfile(req.customer.phone, updateData);
    res.json({
      success: true,
      customer: {
        phone: updated.phone,
        name: updated.name,
        address: updated.address,
        pincode: updated.pincode,
        landmark: updated.landmark
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ─── DYNAMIC MENU APIS ─── */
app.get('/api/menu', async (req, res) => {
  try {
    const menu = await dbAdapter.getMenu();
    res.json({ success: true, menu });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/menu', authenticateAdmin, async (req, res) => {
  const item = req.body;
  if (!item.id || !item.name || !item.cat || !item.variants || item.variants.length === 0) {
    return res.status(400).json({ success: false, error: 'Missing required item fields' });
  }

  try {
    // Generate name-based food image filename if not specified
    const foodImage = (item.image && item.image.trim().length > 0)
      ? item.image.trim()
      : item.name.toLowerCase().replace(/[^a-z0-9]+/g, '_') + '.jpg';

    const formattedVariants = item.variants.map(v => ({
      id: v.id || (item.id + Math.random().toString(36).substring(7)),
      label: v.label,
      price: Number(v.price) || 0,
      cost: Number(v.cost) || 0,
      stock: Number(v.stock) !== undefined ? Number(v.stock) : 100,
      discount: Number(v.discount) || 0
    }));

    const newItem = {
      id: item.id,
      cat: item.cat,
      name: item.name,
      emoji: item.emoji || '',
      desc: item.desc || '',
      veg: item.veg !== undefined ? !!item.veg : true,
      image: foodImage,
      variants: formattedVariants
    };

    await dbAdapter.saveMenuItem(newItem);
    res.json({ success: true, item: newItem });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/menu/:id', authenticateAdmin, async (req, res) => {
  try {
    const deleted = await dbAdapter.deleteMenuItem(req.params.id);
    if (!deleted) return res.status(404).json({ success: false, error: 'Item not found' });
    res.json({ success: true, message: 'Item deleted successfully' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/menu/active', async (req, res) => {
  try {
    let activeSetting;
    if (useMongo) {
      activeSetting = await AdminSettings.findOne({ key: 'menuActive' });
    } else {
      const db = readDB();
      activeSetting = db.menuActive ? { val: JSON.stringify(db.menuActive) } : null;
    }
    const menuActive = activeSetting ? JSON.parse(activeSetting.val) : {};
    res.json({ success: true, menuActive });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/menu/active', authenticateAdmin, async (req, res) => {
  const { itemId, active } = req.body;
  if (itemId === undefined || active === undefined) {
    return res.status(400).json({ success: false, error: 'Missing itemId or active status' });
  }
  try {
    if (useMongo) {
      let activeSetting = await AdminSettings.findOne({ key: 'menuActive' });
      let menuActiveObj = {};
      if (activeSetting) {
        menuActiveObj = JSON.parse(activeSetting.val);
      } else {
        activeSetting = new AdminSettings({ key: 'menuActive', val: '{}' });
      }
      menuActiveObj[itemId] = active;
      activeSetting.val = JSON.stringify(menuActiveObj);
      await activeSetting.save();
    } else {
      const db = readDB();
      if (!db.menuActive) db.menuActive = {};
      db.menuActive[itemId] = active;
      writeDB(db);
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ─── ORDERS MANAGEMENT ─── */
app.get('/api/orders', async (req, res) => {
  const { phone } = req.query;
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ success: false, error: 'Authorization header missing' });
  const token = authHeader.split(' ')[1];

  try {
    // If Admin Token
    if (token === adminSessionToken) {
      const orders = await dbAdapter.getOrders(phone);
      return res.json({ success: true, orders });
    }

    // Customer request
    if (!phone) {
      return res.status(400).json({ success: false, error: 'Phone query required for customer request' });
    }

    // Verify token matches the customer querying the history
    let customer;
    if (useMongo) {
      customer = await Customer.findOne({ sessionToken: token, phone: phone.trim() });
    } else {
      const db = readDB();
      customer = db.customers.find(c => c.sessionToken === token && c.phone === phone.trim());
    }

    if (!customer) {
      return res.status(401).json({ success: false, error: 'Session mismatch or unauthorized request' });
    }

    const orders = await dbAdapter.getOrders(phone);
    res.json({ success: true, orders });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/orders/:id', async (req, res) => {
  try {
    const order = await dbAdapter.getOrderById(req.params.id);
    if (!order) return res.status(404).json({ success: false, error: 'Order not found' });
    res.json({ success: true, order });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/orders', async (req, res) => {
  const { customer, items, pincode, note, couponCode } = req.body;
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ success: false, error: 'Authorization token required' });
  const token = authHeader.split(' ')[1];

  try {
    // Enforce 4 PM to 10 PM operational hours (16:00 to 22:00 local time)
    const currentHour = new Date().getHours();
    if (currentHour < 16 || currentHour >= 22) {
      return res.status(400).json({ success: false, error: 'Kitchen Closed: We only accept orders between 4:00 PM and 10:00 PM.' });
    }

    // Authenticate user session matches checkout phone
    let activeCustomer;
    if (useMongo) {
      activeCustomer = await Customer.findOne({ sessionToken: token, phone: customer?.phone?.trim() });
    } else {
      const db = readDB();
      activeCustomer = db.customers.find(c => c.sessionToken === token && c.phone === customer?.phone?.trim());
    }

    if (!activeCustomer) {
      return res.status(401).json({ success: false, error: 'Authentication failed. Please login before ordering.' });
    }

    if (!validateIndianPhone(customer?.phone)) {
      return res.status(400).json({ success: false, error: 'Invalid Indian phone number' });
    }
    if (!validatePincode(pincode)) {
      return res.status(400).json({ success: false, error: 'Invalid pincode (6 digits required)' });
    }
    if (!customer?.name || customer.name.trim().length < 2) {
      return res.status(400).json({ success: false, error: 'Name is required' });
    }
    if (!customer?.address || customer.address.trim().length < 5) {
      return res.status(400).json({ success: false, error: 'Delivery address is required' });
    }
    if (!items || items.length === 0) {
      return res.status(400).json({ success: false, error: 'Cart is empty' });
    }

    // Re-verify stocks and recalculate subtotals on backend to prevent client-side hacks
    const validatedItems = [];
    let subtotal = 0;
    const menu = await dbAdapter.getMenu();

    for (const item of items) {
      const dbItem = menu.find(m => m.id === item.itemId);
      if (!dbItem) {
        return res.status(400).json({ success: false, error: `Menu item ${item.name} not found` });
      }
      const dbVariant = dbItem.variants.find(v => v.id === item.variantId);
      if (!dbVariant) {
        return res.status(400).json({ success: false, error: `Variant ${item.variant} not found` });
      }

      if (dbVariant.stock < item.qty) {
        return res.status(400).json({ success: false, error: `Stock exhausted: Only ${dbVariant.stock} left for ${item.name}` });
      }

      const itemPrice = Math.max(0, dbVariant.price - (dbVariant.discount || 0));
      subtotal += itemPrice * item.qty;

      validatedItems.push({
        itemId: item.itemId,
        variantId: item.variantId,
        name: dbItem.name,
        variant: dbVariant.label,
        price: itemPrice,
        originalPrice: dbVariant.price,
        cost: dbVariant.cost || 0,
        discount: dbVariant.discount || 0,
        emoji: dbItem.emoji,
        qty: item.qty
      });
    }

    // Apply Coupon discount
    let couponDiscount = 0;
    let couponInfo = null;

    if (couponCode) {
      const coupon = await dbAdapter.getCouponByCode(couponCode);
      if (!coupon || !coupon.isActive) {
        return res.status(400).json({ success: false, error: 'Coupon code is invalid or expired' });
      }
      if (subtotal < coupon.minOrder) {
        return res.status(400).json({ success: false, error: `Coupon requires minimum order of ₹${coupon.minOrder}` });
      }

      if (coupon.type === 'flat') {
        couponDiscount = coupon.value;
      } else if (coupon.type === 'percentage') {
        couponDiscount = Math.round(subtotal * (coupon.value / 100));
      }
      couponDiscount = Math.min(couponDiscount, subtotal); // cap at subtotal

      couponInfo = {
        code: coupon.code,
        discount: couponDiscount
      };
    }

    const finalSubtotal = subtotal - couponDiscount;
    const deliveryInfo = getDeliveryInfo(pincode, finalSubtotal);

    if (!deliveryInfo.serviceable) {
      return res.status(400).json({ success: false, error: 'Sorry, we do not deliver to this pincode' });
    }
    if (finalSubtotal < deliveryInfo.minOrder) {
      return res.status(400).json({ success: false, error: `Minimum order threshold of ₹${deliveryInfo.minOrder} not met` });
    }

    // Deduct stock levels in db
    for (const item of items) {
      const dbItem = menu.find(m => m.id === item.itemId);
      const dbVariant = dbItem.variants.find(v => v.id === item.variantId);
      dbVariant.stock -= item.qty;
      await dbAdapter.saveMenuItem(dbItem);
    }

    const total = finalSubtotal + deliveryInfo.deliveryCharge;
    const orderId = 'ORD' + Date.now().toString().slice(-7);

    // Compute payment breakdown for subscriptions
    const hasTiffin = validatedItems.some(item => {
      const dbItem = menu.find(m => m.id === item.itemId);
      return dbItem && dbItem.cat === 'tiffin';
    });

    const pTerm = hasTiffin ? (req.body.paymentTerm || 'full') : 'full';
    let paidAmount = total;
    let balanceAmount = 0;
    if (pTerm === 'split') {
      paidAmount = Math.round(total * 0.5);
      balanceAmount = total - paidAmount;
    }

    const order = {
      id: orderId,
      customer: {
        name: customer.name.trim(),
        phone: customer.phone.trim(),
        address: customer.address.trim(),
        landmark: (customer.landmark || '').trim()
      },
      items: validatedItems,
      pincode: pincode.trim(),
      zone: deliveryInfo.zone,
      zoneLabel: deliveryInfo.label,
      subtotal: finalSubtotal,
      coupon: couponInfo,
      deliveryCharge: deliveryInfo.deliveryCharge,
      total,
      paymentTerm: pTerm,
      paidAmount,
      balanceAmount,
      note: (note || '').trim(),
      status: 'pending',
      statusHistory: [{ status: 'pending', time: new Date().toISOString() }],
      timestamp: new Date().toISOString()
    };

    await dbAdapter.saveOrder(order);

    // Auto-create subscriptions for tiffin items
    for (const item of validatedItems) {
      const dbItem = menu.find(m => m.id === item.itemId);
      if (dbItem && dbItem.cat === 'tiffin') {
        let slot = req.body.deliverySlot || 'Morning (11:00 AM)';
        if (dbItem.id === 't2') slot = 'Morning (11:00 AM)';
        else if (dbItem.id === 't3') slot = 'Night (8:30 PM)';
        else if (dbItem.id === 't4') slot = 'Both (11:00 AM & 8:30 PM)';

        const priceVal = item.price * item.qty;
        // Proportion of coupon discount applied to this item
        let itemDiscount = 0;
        if (couponDiscount > 0 && subtotal > 0) {
          itemDiscount = Math.round(couponDiscount * ((item.price * item.qty) / subtotal));
        }
        const itemTotal = priceVal - itemDiscount;

        let itemPaid = itemTotal;
        let itemBalance = 0;
        if (pTerm === 'split') {
          itemPaid = Math.round(itemTotal * 0.5);
          itemBalance = itemTotal - itemPaid;
        }

        const subId = 'SUB' + Date.now().toString().slice(-7) + Math.floor(Math.random() * 10);
        const startDate = new Date();
        const endDate = new Date(startDate.getTime() + 30 * 24 * 60 * 60 * 1000); // 30 days only

        const subscription = {
          id: subId,
          orderId: order.id,
          customer: {
            name: order.customer.name,
            phone: order.customer.phone,
            address: order.customer.address,
            landmark: order.customer.landmark
          },
          item: {
            itemId: item.itemId,
            variantId: item.variantId,
            name: item.name,
            variant: item.variant,
            price: item.price,
            qty: item.qty
          },
          status: 'active',
          deliverySlot: slot,
          notes: order.note || '',
          startDate: startDate.toISOString(),
          endDate: endDate.toISOString(),
          durationDays: 30,
          price: priceVal,
          discount: itemDiscount,
          total: itemTotal,
          paymentTerm: pTerm,
          paidAmount: itemPaid,
          balanceAmount: itemBalance,
          deliveries: [],
          history: [{ status: 'active', time: startDate.toISOString() }]
        };
        await dbAdapter.saveSubscription(subscription);
      }
    }

    res.status(201).json({ success: true, order });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put('/api/orders/:id/status', authenticateAdmin, async (req, res) => {
  const { status, rejectReason } = req.body;
  const validStatuses = ['accepted', 'preparing', 'out_for_delivery', 'delivered', 'rejected'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ success: false, error: 'Invalid status' });
  }

  try {
    const order = await dbAdapter.getOrderById(req.params.id);
    if (!order) return res.status(404).json({ success: false, error: 'Order not found' });

    // Restore stock if rejected
    if (status === 'rejected' && order.status !== 'rejected') {
      const menu = await dbAdapter.getMenu();
      for (const item of order.items) {
        const dbItem = menu.find(m => m.id === item.itemId);
        if (dbItem) {
          const dbVariant = dbItem.variants.find(v => v.id === item.variantId);
          if (dbVariant) {
            dbVariant.stock += item.qty;
            await dbAdapter.saveMenuItem(dbItem);
          }
        }
      }
    }

    const updated = await dbAdapter.updateOrderStatus(req.params.id, status, rejectReason);
    res.json({ success: true, order: updated });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/orders/delivered', authenticateAdmin, async (req, res) => {
  try {
    await dbAdapter.clearDeliveredOrders();
    res.json({ success: true, message: 'Delivered orders cleared' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ─── CUSTOMER COUPONS APIS ─── */
app.get('/api/coupons', async (req, res) => {
  try {
    const coupons = await dbAdapter.getCoupons(true); // get active only
    res.json({ success: true, coupons });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ─── ADMIN COUPONS APIS ─── */
app.get('/api/admin/coupons', authenticateAdmin, async (req, res) => {
  try {
    const coupons = await dbAdapter.getCoupons(false); // get all
    res.json({ success: true, coupons });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/admin/coupons', authenticateAdmin, async (req, res) => {
  const { code, type, value, minOrder, isActive, desc } = req.body;
  if (!code || !type || value === undefined) {
    return res.status(400).json({ success: false, error: 'Missing required coupon fields' });
  }

  try {
    const newCoupon = {
      code: code.toUpperCase().trim(),
      type,
      value: Number(value),
      minOrder: Number(minOrder) || 0,
      isActive: isActive !== undefined ? !!isActive : true,
      desc: desc || ''
    };
    await dbAdapter.saveCoupon(newCoupon);
    res.json({ success: true, coupon: newCoupon });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/admin/coupons/:code', authenticateAdmin, async (req, res) => {
  try {
    const deleted = await dbAdapter.deleteCoupon(req.params.code);
    if (!deleted) return res.status(404).json({ success: false, error: 'Coupon not found' });
    res.json({ success: true, message: 'Coupon deleted successfully' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ─── SUBSCRIPTIONS APIS ─── */
app.get('/api/subscriptions', async (req, res) => {
  const { phone } = req.query;
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ success: false, error: 'Authorization header missing' });
  const token = authHeader.split(' ')[1];

  try {
    // If Admin Token
    if (token === adminSessionToken) {
      const subs = await dbAdapter.getSubscriptions(phone);
      return res.json({ success: true, subscriptions: subs });
    }

    // Customer request
    if (!phone) {
      return res.status(400).json({ success: false, error: 'Phone query required for customer request' });
    }

    // Verify token matches the customer querying
    let customer;
    if (useMongo) {
      customer = await Customer.findOne({ sessionToken: token, phone: phone.trim() });
    } else {
      const db = readDB();
      customer = db.customers.find(c => c.sessionToken === token && c.phone === phone.trim());
    }

    if (!customer) {
      return res.status(401).json({ success: false, error: 'Session mismatch or unauthorized request' });
    }

    const subs = await dbAdapter.getSubscriptions(phone);
    res.json({ success: true, subscriptions: subs });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put('/api/subscriptions/:id', async (req, res) => {
  const { id } = req.params;
  const {
    status, address, landmark, notes, deliverySlot, name,
    price, discount, total, paidAmount, balanceAmount, paymentTerm,
    deliveries, durationDays, endDate, pauseStartDate, pauseEndDate
  } = req.body;
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ success: false, error: 'Authorization token required' });
  const token = authHeader.split(' ')[1];

  try {
    const sub = await dbAdapter.getSubscriptionById(id);
    if (!sub) return res.status(404).json({ success: false, error: 'Subscription not found' });

    // Verify authorization: either admin, or matching customer owner
    const isAdmin = token === adminSessionToken;
    let isCustomer = false;
    if (!isAdmin) {
      let customer;
      if (useMongo) {
        customer = await Customer.findOne({ sessionToken: token, phone: sub.customer.phone });
      } else {
        const db = readDB();
        customer = db.customers.find(c => c.sessionToken === token && c.phone === sub.customer.phone);
      }
      if (customer) isCustomer = true;
    }

    if (!isAdmin && !isCustomer) {
      return res.status(401).json({ success: false, error: 'Unauthorized subscription update' });
    }

    // Perform updates
    if (status && status !== sub.status) {
      sub.status = status;
      if (!sub.history) sub.history = [];
      sub.history.push({ status, time: new Date().toISOString() });
    }
    if (name !== undefined) sub.customer.name = name.trim();
    if (address !== undefined) sub.customer.address = address.trim();
    if (landmark !== undefined) sub.customer.landmark = landmark.trim();
    if (notes !== undefined) sub.notes = notes.trim();
    if (deliverySlot !== undefined) sub.deliverySlot = deliverySlot.trim();

    if (price !== undefined) sub.price = Number(price);
    if (discount !== undefined) sub.discount = Number(discount);
    if (total !== undefined) sub.total = Number(total);
    if (paidAmount !== undefined) sub.paidAmount = Number(paidAmount);
    if (balanceAmount !== undefined) sub.balanceAmount = Number(balanceAmount);
    if (paymentTerm !== undefined) sub.paymentTerm = paymentTerm;
    if (deliveries !== undefined) sub.deliveries = deliveries;
    if (durationDays !== undefined) sub.durationDays = Number(durationDays);
    if (endDate !== undefined) sub.endDate = endDate;
    if (pauseStartDate !== undefined) sub.pauseStartDate = pauseStartDate;
    if (pauseEndDate !== undefined) sub.pauseEndDate = pauseEndDate;

    const updated = await dbAdapter.saveSubscription(sub);
    res.json({ success: true, subscription: updated });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/subscriptions/:id', async (req, res) => {
  const { id } = req.params;
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ success: false, error: 'Authorization token required' });
  const token = authHeader.split(' ')[1];

  try {
    const sub = await dbAdapter.getSubscriptionById(id);
    if (!sub) return res.status(404).json({ success: false, error: 'Subscription not found' });

    // Verify authorization: either admin, or matching customer owner
    const isAdmin = token === adminSessionToken;
    let isCustomer = false;
    if (!isAdmin) {
      let customer;
      if (useMongo) {
        customer = await Customer.findOne({ sessionToken: token, phone: sub.customer.phone });
      } else {
        const db = readDB();
        customer = db.customers.find(c => c.sessionToken === token && c.phone === sub.customer.phone);
      }
      if (customer) isCustomer = true;
    }

    if (!isAdmin && !isCustomer) {
      return res.status(401).json({ success: false, error: 'Unauthorized subscription deletion' });
    }

    await dbAdapter.deleteSubscription(id);
    res.json({ success: true, message: 'Subscription deleted successfully' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ─── ADMIN AUTHENTICATION ─── */
app.post('/api/admin/login', async (req, res) => {
  const { password } = req.body;
  try {
    const storedHash = await dbAdapter.getAdminPass();
    if (verifyPassword(password, storedHash)) {
      res.json({ success: true, token: adminSessionToken, message: 'Admin login successful' });
    } else {
      res.status(401).json({ success: false, error: 'Invalid admin password' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/settings/marquee', async (req, res) => {
  try {
    let marqueeSetting;
    if (useMongo) {
      marqueeSetting = await AdminSettings.findOne({ key: 'marqueeText' });
    } else {
      const db = readDB();
      marqueeSetting = db.marqueeText ? { val: db.marqueeText } : null;
    }
    const marqueeText = marqueeSetting ? marqueeSetting.val : [
      "380051 Bakery City: FREE Delivery on ₹99+ Orders!",
      "Other Ahmedabad: FREE Delivery on ₹149+ Orders!",
      "Authentic Bihari & Nepali Food — Fresh Daily!",
      "Monthly Tiffin Available – Starting ₹2,199",
      "Orders ₹399+ Get 2 Free Samosa!"
    ].join('\n');
    res.json({ success: true, marqueeText });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/settings/marquee', authenticateAdmin, async (req, res) => {
  const { marqueeText } = req.body;
  if (marqueeText === undefined) {
    return res.status(400).json({ success: false, error: 'Missing marqueeText' });
  }
  try {
    if (useMongo) {
      await AdminSettings.updateOne(
        { key: 'marqueeText' },
        { $set: { val: marqueeText } },
        { upsert: true }
      );
    } else {
      const db = readDB();
      db.marqueeText = marqueeText;
      writeDB(db);
    }
    res.json({ success: true, message: 'Marquee text updated successfully' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/admin/change-password', authenticateAdmin, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ success: false, error: 'New password must be at least 6 characters' });
  }
  try {
    const newHash = hashPassword(newPassword);
    await dbAdapter.saveAdminPass(newHash);
    res.json({ success: true, message: 'Admin password changed successfully' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/admin/upload-image', authenticateAdmin, (req, res) => {
  const { fileName, base64Data } = req.body;
  if (!fileName || !base64Data) {
    return res.status(400).json({ success: false, error: 'fileName and base64Data are required' });
  }

  // Validate filename to prevent path traversal
  const safeFileName = path.basename(fileName).replace(/[^a-zA-Z0-9_.-]/g, '');
  if (!safeFileName) {
    return res.status(400).json({ success: false, error: 'Invalid file name' });
  }

  // Extract content after data URI prefix if present
  let cleanBase64 = base64Data;
  if (base64Data && base64Data.includes(',')) {
    cleanBase64 = base64Data.split(',')[1];
  }

  const buffer = Buffer.from(cleanBase64, 'base64');
  const targetPath = path.join(__dirname, safeFileName);

  fs.writeFile(targetPath, buffer, (err) => {
    if (err) {
      return res.status(500).json({ success: false, error: 'Failed to write image file: ' + err.message });
    }
    res.json({ success: true, fileName: safeFileName, imagePath: safeFileName });
  });
});

/* ─── SALES & PROFIT STATISTICS ─── */
app.get('/api/stats', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ success: false, error: 'Authorization header missing' });
  const token = authHeader.split(' ')[1];
  if (token !== adminSessionToken) return res.status(401).json({ success: false, error: 'Unauthorized stats request' });

  try {
    const orders = await dbAdapter.getOrders();
    const today = new Date().toDateString();
    
    // Today's stats
    const todayOrders = orders.filter(o => new Date(o.timestamp).toDateString() === today);
    const todayDelivered = todayOrders.filter(o => o.status === 'delivered');
    const todayRevenue = todayDelivered.reduce((sum, o) => sum + o.total, 0);
    const todayCost = todayDelivered.reduce((sum, o) => {
      return sum + o.items.reduce((itemSum, item) => itemSum + ((item.cost || 0) * item.qty), 0);
    }, 0);
    const todayProfit = todayRevenue - todayCost;
    const todayPending = orders.filter(o => ['pending','accepted','preparing','out_for_delivery'].includes(o.status)).length;

    // All-time stats
    const allDelivered = orders.filter(o => o.status === 'delivered');
    const allRevenue = allDelivered.reduce((sum, o) => sum + o.total, 0);
    const allCost = allDelivered.reduce((sum, o) => {
      return sum + o.items.reduce((itemSum, item) => itemSum + ((item.cost || 0) * item.qty), 0);
    }, 0);
    const allProfit = allRevenue - allCost;
    const allRejected = orders.filter(o => o.status === 'rejected').length;

    res.json({
      success: true,
      stats: {
        today: {
          orders: todayOrders.length,
          revenue: todayRevenue,
          cost: todayCost,
          profit: todayProfit,
          margin: todayRevenue > 0 ? Math.round((todayProfit / todayRevenue) * 100) : 0,
          delivered: todayDelivered.length,
          pending: todayPending
        },
        allTime: {
          orders: orders.length,
          revenue: allRevenue,
          cost: allCost,
          profit: allProfit,
          margin: allRevenue > 0 ? Math.round((allProfit / allRevenue) * 100) : 0,
          delivered: allDelivered.length,
          rejected: allRejected
        }
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ─── Start Server ─── */
app.listen(PORT, () => {
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  🥟  Bihar & Nepal Momo Express — Backend  ');
  console.log('  ❤️   Har Swad Mein Maa Ka Haath           ');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`  ✅  Server running at: http://localhost:${PORT}`);
  console.log(`  🌐  Customer site:     http://localhost:${PORT}/index.html`);
  console.log(`  🔐  Admin panel:       http://localhost:${PORT}/admin.html`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
});
