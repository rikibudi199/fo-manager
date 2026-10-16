const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'rahasia_fo_field_manager_2026';

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// --- MANAJEMEN KONEKSI MONGODB (SERVERLESS READY) ---
let isConnected = false;

async function connectToDatabase() {
    if (isConnected && mongoose.connection.readyState === 1) {
        return;
    }
    
    try {
        const db = await mongoose.connect(process.env.MONGODB_URI, {
            serverSelectionTimeoutMS: 5000,
            bufferCommands: false
        });
        isConnected = db.connections[0].readyState;
        console.log('✅ Berhasil terhubung ke MongoDB Atlas Cloud!');
        await createDefaultAdmin();
    } catch (err) {
        console.error('❌ Gagal terhubung ke MongoDB:', err);
    }
}

// Middleware wajib untuk memastikan koneksi database aktif pada setiap request
app.use(async (req, res, next) => {
    await connectToDatabase();
    next();
});

// Skema Database
const deviceSchema = new mongoose.Schema({
    name: { type: String, required: true },
    type: { type: String, required: true },
    lat: { type: Number, required: true },
    lng: { type: Number, required: true },
    details: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { timestamps: true });

const cableSchema = new mongoose.Schema({
    name: { type: String, required: true },
    points: { type: Array, required: true },
    details: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { timestamps: true });

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'technician'], default: 'technician' }
}, { timestamps: true });

const Device = mongoose.models.Device || mongoose.model('Device', deviceSchema);
const Cable = mongoose.models.Cable || mongoose.model('Cable', cableSchema);
const User = mongoose.models.User || mongoose.model('User', userSchema);

// Otomatis Buat Akun Admin Default
async function createDefaultAdmin() {
    try {
        const adminExist = await User.findOne({ username: 'admin' });
        if (!adminExist) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await User.create({ username: 'admin', password: hashedPassword, role: 'admin' });
            console.log('👤 Akun Default dibuat -> Username: admin | Password: admin123');
        }
    } catch (err) {
        console.error('Gagal membuat admin default:', err);
    }
}

// Middleware Verifikasi Auth
function verifyAuth(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ success: false, message: 'Silakan login terlebih dahulu.' });
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(403).json({ success: false, message: 'Sesi habis atau token tidak valid.' });
    }
}

// Middleware Verifikasi Khusus Admin
function verifyAdmin(req, res, next) {
    verifyAuth(req, res, () => {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Akses ditolak! Hanya Admin yang diizinkan.' });
        }
        next();
    });
}

// --- API AUTHENTICATION ---
app.post('/api/auth/register', verifyAdmin, async (req, res) => {
    try {
        const { username, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const newUser = new User({
            username,
            password: hashedPassword,
            role: role || 'technician'
        });
        
        await newUser.save();
        res.json({ success: true, message: 'Akun berhasil dibuat!' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Username sudah digunakan atau terjadi kesalahan.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ success: false, message: 'Username atau password salah!' });
        }
        
        const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
        
        res.cookie('token', token, { httpOnly: true });
        res.json({ success: true, message: 'Login berhasil!', role: user.role, username: user.username });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/auth/me', async (req, res) => {
    try {
        const token = req.cookies.token;
        if (!token) return res.json({ loggedIn: false });
        
        const decoded = jwt.verify(token, JWT_SECRET);
        res.json({ loggedIn: true, username: decoded.username, role: decoded.role });
    } catch (error) {
        res.json({ loggedIn: false });
    }
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true, message: 'Berhasil logout' });
});

// --- API DATA DEVICES & CABLES ---
app.get('/api/devices', async (req, res) => {
    try {
        const devices = await Device.find();
        const cables = await Cable.find();
        res.json({ success: true, devices, cables });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/devices', verifyAdmin, async (req, res) => {
    try {
        const newDevice = new Device(req.body);
        await newDevice.save();
        res.json({ success: true, device: newDevice });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/devices/:id', verifyAdmin, async (req, res) => {
    try {
        const updated = await Device.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json({ success: true, device: updated });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.delete('/api/devices/:id', verifyAdmin, async (req, res) => {
    try {
        await Device.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: 'Perangkat dihapus' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/cables', verifyAdmin, async (req, res) => {
    try {
        const newCable = new Cable(req.body);
        await newCable.save();
        res.json({ success: true, cable: newCable });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/cables/:id', verifyAdmin, async (req, res) => {
    try {
        const updated = await Cable.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json({ success: true, cable: updated });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.delete('/api/cables/:id', verifyAdmin, async (req, res) => {
    try {
        await Cable.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: 'Kabel dihapus' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.delete('/api/reset-map', verifyAdmin, async (req, res) => {
    try {
        await Device.deleteMany({});
        await Cable.deleteMany({});
        res.json({ success: true, message: 'Peta dikosongkan' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Ekspor modul untuk Vercel, dan jalankan server lokal jika diakses langsung
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`🚀 Server berjalan di http://localhost:${PORT}`);
    });
}

module.exports = app;