const express = require('express');
const sql = require('mssql');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(__dirname));

const SECRET_KEY = 'NLB_SECRET_TOKEN_2026';

const dbConfig = {
user: 'sa',
password: '1',
server: 'localhost',
database: 'NLB', // Если у тебя база называется NLB_Club, измени здесь
options: { encrypt: true, trustServerCertificate: true }
};

function hash(password) {
return crypto.createHash('sha256').update(password).digest('hex');
}

// ИСПРАВЛЕНО: Правильная проверка токена
function authenticateToken(req, res, next) {
const authHeader = req.headers['authorization'];
const token = authHeader && authHeader.split(' ')[1];
if (!token) return res.status(401).json({ success: false, message: 'Нет доступа' });

jwt.verify(token, SECRET_KEY, (err, decoded) => {
if (err) return res.status(403).json({ success: false, message: 'Токен недействителен' });
req.user = { id: decoded.userId, role: decoded.role }; // Сохраняем id и role
next();
});
}

// Регистрация
app.post('/register', async (req, res) => {
const { username, password, firstName, lastName, phone } = req.body;
try {
let pool = await sql.connect(dbConfig);
let checkUser = await pool.request().input('u', sql.NVarChar, username).query('SELECT ID_user FROM Users WHERE Login = @u');
if (checkUser.recordset.length > 0) return res.status(400).json({ success: false, message: 'Логин уже занят' });

const userHash = hash(password);
let insertResult = await pool.request()
.input('role', sql.Int, 2)
.input('u', sql.NVarChar, username)
.input('p', sql.NVarChar, userHash)
.input('fn', sql.NVarChar, firstName)
.input('ln', sql.NVarChar, lastName)
.input('ph', sql.NVarChar, phone)
.query(`
INSERT INTO Users (ID_role, Login, Password, First_name, Last_name, Phone)
VALUES (@role, @u, @p, @fn, @ln, @ph);
SELECT SCOPE_IDENTITY() AS NewUserId;
`);

const userId = insertResult.recordset[0].NewUserId;
const token = jwt.sign({ userId: userId, role: 2 }, SECRET_KEY, { expiresIn: '24h' });
res.json({ success: true, token, userId });
} catch (err) {
console.error(err);
res.status(500).json({ success: false, message: 'Ошибка сервера' });
}
});

// Авторизация (Вход)
app.post('/login', async (req, res) => {
const { username, password } = req.body;
try {
let pool = await sql.connect(dbConfig);

let checkUser = await pool.request()
.input('u', sql.NVarChar, username)
.query('SELECT ID_user FROM Users WHERE Login = @u');

if (checkUser.recordset.length === 0) {
return res.status(401).json({ success: false, message: 'Аккаунт не найден. Перейдите во вкладку "Регистрация"' });
}

const userHash = hash(password);
let result = await pool.request()
.input('u', sql.NVarChar, username)
.input('p', sql.NVarChar, userHash)
.query('SELECT ID_user, ID_role FROM Users WHERE Login = @u AND Password = @p');

if (result.recordset.length > 0) {
const user = result.recordset[0];
const token = jwt.sign({ userId: user.ID_user, role: user.ID_role }, SECRET_KEY, { expiresIn: '24h' });
res.json({ success: true, token, role: user.ID_role });
} else {
res.status(401).json({ success: false, message: 'Неверный пароль' });
}
} catch (err) {
console.error(err);
res.status(500).json({ success: false, message: 'Ошибка сервера' });
}
});

// Оформление подписки (Оплата)
app.post('/api/pay', authenticateToken, async (req, res) => {
const { tariffId, cardNumber } = req.body;
const userId = req.user.id;
const cardMask = '**** **** **** ' + cardNumber.slice(-4);

try {
let pool = await sql.connect(dbConfig);

let tariffRes = await pool.request()
.input('id', sql.Int, tariffId)
.query('SELECT Price, Duration FROM Tariffs WHERE ID_tariff = @id');

if (tariffRes.recordset.length === 0) {
return res.status(400).json({success: false, message: 'Тариф не найден в базе данных'});
}
const tariff = tariffRes.recordset[0];

// Запись транзакции
await pool.request()
.input('user', sql.Int, userId)
.input('tariff', sql.Int, tariffId)
.input('amount', sql.Decimal, tariff.Price)
.input('mask', sql.NVarChar, cardMask)
.input('status', sql.NVarChar, 'Успешно')
.query(`
INSERT INTO Transactions (ID_user, ID_tariff, Amount, Payment_date, Card_mask, Payment_status)
VALUES (@user, @tariff, @amount, GETDATE(), @mask, @status)
`);

// Активация подписки (УБЕДИСЬ, ЧТО Status ЕСТЬ В БД)
await pool.request()
.input('user', sql.Int, userId)
.input('tariff', sql.Int, tariffId)
.input('days', sql.Int, tariff.Duration)
.query(`
INSERT INTO Subscriptions (ID_user, ID_tariff, Start_date, End_date, Status)
VALUES (@user, @tariff, GETDATE(), DATEADD(day, @days, GETDATE()), 'Активна')
`);

res.json({ success: true, message: 'Оплата успешно завершена' });
} catch (err) {
console.error("\n❌ ОШИБКА ПРИ ОПЛАТЕ:", err.message, "\n");
res.status(500).json({ success: false, message: 'Ошибка сервера при оплате' });
}
});

// Получение данных для Личного Кабинета
app.get('/api/user/profile', authenticateToken, async (req, res) => {
try {
let pool = await sql.connect(dbConfig);

let userRes = await pool.request()
.input('id', sql.Int, req.user.id)
.query('SELECT First_name, Last_name, Phone, Registration_date FROM Users WHERE ID_user = @id');

let subRes = await pool.request()
.input('id', sql.Int, req.user.id)
.query(`
SELECT t.Name as TariffName, s.Start_date, s.End_date, s.Status
FROM Subscriptions s
JOIN Tariffs t ON s.ID_tariff = t.ID_tariff
WHERE s.ID_user = @id
ORDER BY s.End_date DESC
`);

if (userRes.recordset.length > 0) {
res.json({
success: true,
user: userRes.recordset[0],
subscriptions: subRes.recordset
});
} else {
res.status(404).json({ success: false, message: 'Пользователь не найден' });
}

} catch (err) {
console.error(err);
res.status(500).json({ success: false });
}
});

// Гостевой визит
app.post('/api/guest', async (req, res) => {
const { name, phone } = req.body;
try {
let pool = await sql.connect(dbConfig);
await pool.request()
.input('n', sql.NVarChar, name)
.input('p', sql.NVarChar, phone)
.query('INSERT INTO Guest_Visits (Name, Phone) VALUES (@n, @p)');
res.json({ success: true });
} catch (err) {
console.error(err);
res.status(500).json({ success: false });
}
});

// Таймер акций
app.get('/api/promo', async (req, res) => {
try {
let pool = await sql.connect(dbConfig);
let result = await pool.request().query(`
SELECT TOP 1 Title, End_date
FROM Promotions
WHERE Is_active = 1 AND End_date > GETDATE()
ORDER BY End_date ASC
`);
if (result.recordset.length > 0) {
res.json({ success: true, data: result.recordset[0] });
} else {
res.json({ success: false, message: 'Нет активных акций' });
}
} catch (err) {
res.status(500).json({ success: false });
}
});

// Админка: Транзакции
app.get('/api/admin/transactions', authenticateToken, async (req, res) => {
if (req.user.role !== 1) return res.status(403).json({ success: false, message: 'Доступ закрыт' });
try {
let pool = await sql.connect(dbConfig);
let result = await pool.request().query(`
SELECT t.ID_transaction, u.First_name, u.Last_name, tar.Name as TariffName, t.Amount, t.Payment_date
FROM Transactions t
JOIN Users u ON t.ID_user = u.ID_user
JOIN Tariffs tar ON t.ID_tariff = tar.ID_tariff
ORDER BY t.Payment_date DESC
`);
res.json({ success: true, data: result.recordset });
} catch (err) {
console.error(err);
res.status(500).json({ success: false });
}
});

// Админка: Новая акция
app.post('/api/admin/promo', authenticateToken, async (req, res) => {
if (req.user.role !== 1) return res.status(403).json({ success: false });
const { title, discount, endDate } = req.body;
try {
let pool = await sql.connect(dbConfig);
await pool.request().query('UPDATE Promotions SET Is_active = 0');
await pool.request()
.input('t', sql.NVarChar, title)
.input('d', sql.Int, discount)
.input('e', sql.DateTime, endDate)
.query('INSERT INTO Promotions (Title, Discount_percent, Start_date, End_date, Is_active) VALUES (@t, @d, GETDATE(), @e, 1)');
res.json({ success: true });
} catch (err) {
console.error(err);
res.status(500).json({ success: false });
}
});

// Админка: Пользователи
app.get('/api/admin/users', authenticateToken, async (req, res) => {
if (req.user.role !== 1) return res.status(403).json({ success: false, message: 'Доступ только для администратора' });
try {
let pool = await sql.connect(dbConfig);
let result = await pool.request().query('SELECT ID_user, First_name, Last_name, Phone, Registration_date FROM Users WHERE ID_role = 2');
res.json({ success: true, data: result.recordset });
} catch (err) {
res.status(500).json({ success: false });
}
});

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(3000, () => {
console.log('Сервер запущен: http://localhost:3000');
console.log('Панель администратора: http://localhost:3000/admin');
});