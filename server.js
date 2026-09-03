require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { z } = require('zod');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 4000;
const DATA_FILE = path.join(__dirname, 'data.json');

// Ensure data file exists
if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify({
        users: [],
        loans: [],
        withdrawals: [],
        transactions: []
    }, null, 2));
}

// Read/write data functions
function readData() {
    try {
        return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    } catch {
        return { users: [], loans: [], withdrawals: [], transactions: [] };
    }
}

function writeData(data) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({
    origin: '*',
    credentials: true
}));
app.use(express.json({ limit: '100kb' }));

// Serve static files from root
app.use(express.static(__dirname));

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: true
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: true
});

// Validation schemas
const reg = z.object({
    fullName: z.string().trim().min(2).max(120),
    email: z.string().trim().email().max(320),
    phone: z.string().trim().min(7).max(40),
    password: z.string().min(8).max(128)
});

const login = z.object({
    email: z.string().trim().email(),
    password: z.string().min(1).max(128)
});

const loan = z.object({
    applicantName: z.string().trim().min(2).max(120),
    country: z.string().trim().min(2).max(100),
    addressTitle: z.string().trim().min(3).max(500),
    city: z.string().trim().min(2).max(100),
    stateRegion: z.string().trim().min(2).max(100),
    phone: z.string().trim().min(7).max(40),
    email: z.string().trim().email(),
    monthlyIncome: z.coerce.number().positive(),
    loanAmount: z.coerce.number().positive(),
    currency: z.enum(['NGN', 'USD', 'GBP', 'EUR', 'GHS', 'KES', 'ZAR']),
    loanPeriodYears: z.coerce.number().int().min(1).max(10),
    purpose: z.string().trim().min(3).max(1000)
});

const withdrawal = z.object({
    amount: z.coerce.number().positive(),
    destination: z.string().trim().min(5).max(1000)
});

function parsed(schema, body, res) {
    const x = schema.safeParse(body);
    if (!x.success) {
        res.status(400).json({
            error: 'Validation failed',
            details: x.error.flatten()
        });
        return null;
    }
    return x.data;
}

function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
}

function estimate(amount, years, rate = 0.12) {
    const interest = amount * rate * years;
    const total = amount + interest;
    return {
        interest,
        total,
        monthly: total / (years * 12)
    };
}

// Auth middleware
function auth(req, res, next) {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const data = readData();
        const user = data.users.find(u => u.id === decoded.sub);
        if (!user || user.status !== 'active') {
            return res.status(401).json({ error: 'Account unavailable' });
        }
        req.user = user;
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

function adminAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'Admin authentication required' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        req.admin = decoded;
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid admin token' });
    }
}

// Health check
app.get('/api/health', (req, res) => {
    res.json({ ok: true, service: 'oceanic-lending-api' });
});

// Admin login
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
        const token = jwt.sign(
            { role: 'admin', type: 'admin' },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        res.json({ token, role: 'admin' });
    } else {
        res.status(401).json({ error: 'Invalid admin credentials' });
    }
});

// Admin dashboard data
app.get('/api/admin/dashboard', adminAuth, (req, res) => {
    const data = readData();
    res.json({
        users: data.users,
        loans: data.loans,
        withdrawals: data.withdrawals,
        transactions: data.transactions
    });
});

// Admin update loan status
app.patch('/api/admin/loans/:id', adminAuth, (req, res) => {
    const { status, reviewerNote } = req.body;
    if (!['under_review', 'approved', 'rejected', 'cancelled'].includes(status)) {
        return res.status(400).json({ error: 'Invalid loan status' });
    }

    const data = readData();
    const loan = data.loans.find(l => l.id === req.params.id);
    if (!loan) {
        return res.status(404).json({ error: 'Loan not found' });
    }

    loan.status = status;
    loan.reviewerNote = reviewerNote || null;
    loan.updatedAt = new Date().toISOString();

    // If approved, add to user's balance
    if (status === 'approved') {
        const user = data.users.find(u => u.id === loan.userId);
        if (user) {
            user.balance = (user.balance || 0) + loan.loanAmount;
            data.transactions.push({
                id: generateId(),
                userId: user.id,
                type: 'loan_disbursement',
                amount: loan.loanAmount,
                currency: loan.currency,
                status: 'completed',
                reference: `LN-${generateId()}`,
                description: `Loan approved and disbursed`,
                createdAt: new Date().toISOString()
            });
        }
    }

    writeData(data);
    res.json({ loan });
});

// Admin update withdrawal status
app.patch('/api/admin/withdrawals/:id', adminAuth, (req, res) => {
    const { status, reviewerNote } = req.body;
    if (!['pending', 'processing', 'completed', 'rejected', 'cancelled'].includes(status)) {
        return res.status(400).json({ error: 'Invalid withdrawal status' });
    }

    const data = readData();
    const withdrawal = data.withdrawals.find(w => w.id === req.params.id);
    if (!withdrawal) {
        return res.status(404).json({ error: 'Withdrawal not found' });
    }

    withdrawal.status = status;
    withdrawal.reviewerNote = reviewerNote || null;
    withdrawal.updatedAt = new Date().toISOString();

    // If rejected, return funds to user
    if (status === 'rejected' || status === 'cancelled') {
        const user = data.users.find(u => u.id === withdrawal.userId);
        if (user) {
            user.balance = (user.balance || 0) + withdrawal.amount;
            data.transactions.push({
                id: generateId(),
                userId: user.id,
                type: 'withdrawal_reversal',
                amount: withdrawal.amount,
                currency: withdrawal.currency,
                status: 'completed',
                reference: `RV-${generateId()}`,
                description: `Withdrawal reversed: ${withdrawal.reference}`,
                createdAt: new Date().toISOString()
            });
        }
    }

    writeData(data);
    res.json({ withdrawal });
});

// User registration
app.post('/api/auth/register', authLimiter, async (req, res) => {
    const d = parsed(reg, req.body, res);
    if (!d) return;

    const data = readData();
    if (data.users.find(u => u.email === d.email)) {
        return res.status(409).json({ error: 'Account already exists' });
    }

    const hashedPassword = await bcrypt.hash(d.password, 10);
    const user = {
        id: generateId(),
        fullName: d.fullName,
        email: d.email,
        phone: d.phone,
        password: hashedPassword,
        balance: 0,
        currency: 'NGN',
        status: 'active',
        createdAt: new Date().toISOString()
    };

    data.users.push(user);
    writeData(data);

    const token = jwt.sign(
        { sub: user.id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
    );

    res.status(201).json({
        user: {
            id: user.id,
            fullName: user.fullName,
            email: user.email,
            phone: user.phone,
            balance: user.balance
        },
        token
    });
});

// User login
app.post('/api/auth/login', authLimiter, async (req, res) => {
    const d = parsed(login, req.body, res);
    if (!d) return;

    const data = readData();
    const user = data.users.find(u => u.email === d.email);
    if (!user || !(await bcrypt.compare(d.password, user.password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.status !== 'active') {
        return res.status(403).json({ error: 'Account unavailable' });
    }

    const token = jwt.sign(
        { sub: user.id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
    );

    res.json({
        user: {
            id: user.id,
            fullName: user.fullName,
            email: user.email,
            phone: user.phone,
            balance: user.balance
        },
        token
    });
});

// Get user profile
app.get('/api/me', auth, (req, res) => {
    res.json({
        user: {
            id: req.user.id,
            fullName: req.user.fullName,
            email: req.user.email,
            phone: req.user.phone,
            balance: req.user.balance,
            currency: req.user.currency
        }
    });
});

// Get wallet
app.get('/api/wallet', auth, (req, res) => {
    const data = readData();
    const user = data.users.find(u => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    const transactions = data.transactions
        .filter(t => t.userId === req.user.id)
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.json({
        wallet: {
            balance: user.balance,
            currency: user.currency || 'NGN'
        },
        transactions: transactions.slice(0, 50)
    });
});

// Get user loans
app.get('/api/loans', auth, (req, res) => {
    const data = readData();
    const loans = data.loans
        .filter(l => l.userId === req.user.id)
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json({ loans });
});

// Create loan application
app.post('/api/loans', auth, (req, res) => {
    const d = parsed(loan, req.body, res);
    if (!d) return;

    const data = readData();
    const user = data.users.find(u => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    const estimateData = estimate(d.loanAmount, d.loanPeriodYears);
    const loanApplication = {
        id: generateId(),
        userId: req.user.id,
        ...d,
        status: 'under_review',
        estimatedInterest: estimateData.interest,
        estimatedTotalRepayment: estimateData.total,
        estimatedMonthlyPayment: estimateData.monthly,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };

    data.loans.push(loanApplication);
    writeData(data);

    res.status(201).json({ loan: loanApplication });
});

// Get user withdrawals
app.get('/api/withdrawals', auth, (req, res) => {
    const data = readData();
    const withdrawals = data.withdrawals
        .filter(w => w.userId === req.user.id)
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json({ withdrawals });
});

// Create withdrawal request
app.post('/api/withdrawals', auth, (req, res) => {
    const d = parsed(withdrawal, req.body, res);
    if (!d) return;

    const data = readData();
    const user = data.users.find(u => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    if (d.amount > user.balance) {
        return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Deduct balance immediately (pending approval)
    user.balance -= d.amount;

    const withdrawalRequest = {
        id: generateId(),
        userId: req.user.id,
        amount: d.amount,
        currency: user.currency || 'NGN',
        destination: d.destination,
        reference: `WD-${generateId()}`,
        status: 'pending',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };

    data.withdrawals.push(withdrawalRequest);
    data.transactions.push({
        id: generateId(),
        userId: req.user.id,
        type: 'withdrawal',
        amount: d.amount,
        currency: user.currency || 'NGN',
        status: 'pending',
        reference: withdrawalRequest.reference,
        description: `Withdrawal request submitted`,
        createdAt: new Date().toISOString()
    });

    writeData(data);
    res.status(201).json({
        reference: withdrawalRequest.reference,
        status: 'pending'
    });
});

// Serve admin.html and index.html from root
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.listen(PORT, () => {
    console.log(`✅ Oceanic API running on port ${PORT}`);
    console.log(`🔗 Admin panel: http://localhost:${PORT}/admin`);
    console.log(`📡 API: http://localhost:${PORT}/api`);
});
