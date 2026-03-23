const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// ================= DATABASE =================
const db = mysql.createConnection({
    host: 'YOUR_DB_HOST',
    user: 'YOUR_DB_USER',
    password: 'YOUR_DB_PASSWORD',
    database: 'YOUR_DB_NAME'
});

db.connect(err => {
    if (err) {
        console.log("DB Error:", err);
    } else {
        console.log("Database Connected");
    }
});

// ================= AUTH MIDDLEWARE =================
function auth(req, res, next){
    const token = req.headers['authorization'];

    if(!token) return res.send("No Token");

    try {
        const verified = jwt.verify(token, "SECRET_KEY");
        req.user = verified;
        next();
    } catch {
        res.send("Invalid Token");
    }
}

// ================= ROLE CHECK =================
function role(...allowed){
    return (req,res,next)=>{
        if(!allowed.includes(req.user.role)){
            return res.send("Permission Denied");
        }
        next();
    }
}

// ================= REGISTER =================
app.post('/register', async (req, res)=>{
    const { name, mobile, password, role } = req.body;

    const hash = await bcrypt.hash(password, 10);

    db.query(
        "INSERT INTO users (name, mobile, password, role) VALUES (?, ?, ?, ?)",
        [name, mobile, hash, role],
        (err)=>{
            if(err) return res.send(err);
            res.send("User Registered");
        }
    );
});

// ================= LOGIN =================
app.post('/login', (req,res)=>{
    const { mobile, password } = req.body;

    db.query(
        "SELECT * FROM users WHERE mobile=?",
        [mobile],
        async (err, result)=>{
            if(result.length === 0) return res.send("User Not Found");

            const valid = await bcrypt.compare(password, result[0].password);
            if(!valid) return res.send("Wrong Password");

            const token = jwt.sign(
                {
                    id: result[0].id,
                    role: result[0].role,
                    state_id: result[0].state_id
                },
                "SECRET_KEY",
                { expiresIn: "1h" }
            );

            res.json({ token });
        }
    );
});

// ================= CREATE RETAILER =================
app.post('/create-retailer', auth, role('asm','sales_executive'), (req,res)=>{
    const { name, mobile } = req.body;

    db.query(
        "INSERT INTO users (name, mobile, role, created_by) VALUES (?, ?, 'retailer', ?)",
        [name, mobile, req.user.id],
        (err)=>{
            if(err) return res.send(err);
            res.send("Retailer Created");
        }
    );
});

// ================= USERS LIST =================
app.get('/users', auth, (req,res)=>{
    db.query("SELECT name, role FROM users", (err,result)=>{
        res.json(result);
    });
});

// ================= STATE DATA =================
app.get('/state-data', auth, role('state_head'), (req,res)=>{
    db.query(
        "SELECT * FROM users WHERE state_id=?",
        [req.user.state_id],
        (err,result)=>{
            res.json(result);
        }
    );
});

// ================= WALLET ADD =================
app.post('/add-money', auth, (req,res)=>{
    const { amount } = req.body;

    db.query(
        "UPDATE wallets SET balance = balance + ? WHERE user_id=?",
        [amount, req.user.id],
        ()=>{
            res.send("Money Added");
        }
    );
});

// ================= STATS =================
app.get('/stats', auth, (req,res)=>{
    db.query("SELECT COUNT(*) as users FROM users", (e,u)=>{
        db.query("SELECT SUM(amount) as income FROM transactions", (e2,t)=>{
            res.json({
                users: u[0].users,
                income: t[0].income || 0
            });
        });
    });
});

// ================= SERVER =================
const PORT = process.env.PORT || 3000;

app.listen(PORT, ()=>{
    console.log("Server Running on port", PORT);
});
