require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const AWS = require('aws-sdk');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const axios = require('axios');
const CryptoJS = require('crypto-js');

const app = express();
app.use(cors());
app.use(express.json());

// =================================================================
// ★ 환경변수 설정
// =================================================================
const ACCESS_KEY = process.env.NCP_ACCESS_KEY;
const SECRET_KEY = process.env.NCP_SECRET_KEY;
const KMS_KEY_TAG = process.env.NCP_KMS_KEY_TAG;

const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_USER = process.env.GOOGLE_USER;
const GOOGLE_PASS = process.env.GOOGLE_PASS;

// ★ 중요: 본인의 Image Optimizer (CDN) 주소로 꼭 확인하세요!
const GLOBAL_EDGE_URL = 'http://9wfjhaxp13723.edge.naverncp.com'; 

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

const S3 = new AWS.S3({
    endpoint: new AWS.Endpoint('https://kr.object.ncloudstorage.com'),
    region: 'kr-standard',
    signatureVersion: 'v4',
    credentials: { accessKeyId: ACCESS_KEY, secretAccessKey: SECRET_KEY }
});

const transporter = nodemailer.createTransport({
    service: 'gmail', auth: { user: GOOGLE_USER, pass: GOOGLE_PASS }
});

// =================================================================
// ★ KMS 암호화/복호화 로직
// =================================================================
function makeSignature(method, url, timestamp) {
    const space = " ";
    const newLine = "\n";
    const hmac = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, SECRET_KEY);
    hmac.update(method); hmac.update(space); hmac.update(url); hmac.update(newLine); hmac.update(timestamp); hmac.update(newLine); hmac.update(ACCESS_KEY);
    const hash = hmac.finalize();
    return hash.toString(CryptoJS.enc.Base64);
}

// 1. 암호화 함수
async function encryptKMS(plainText) {
    if (!plainText) return plainText;
    const url = `/kms/v1/keys/${KMS_KEY_TAG}/encrypt`;
    const timestamp = Date.now().toString();
    const signature = makeSignature('POST', url, timestamp);
    const plainText64 = Buffer.from(plainText, 'utf8').toString('base64');

    try {
        const res = await axios.post(`https://ocapi.ncloud.com${url}`,
        { plaintext: plainText64 },
        {
            headers: { 'x-ncp-apigw-timestamp': timestamp, 'x-ncp-iam-access-key': ACCESS_KEY, 'x-ncp-apigw-signature-v2': signature, 'Content-Type': 'application/json' }
        });

        if (!res.data.data || !res.data.data.ciphertext) {
             throw new Error("KMS 응답에 ciphertext가 없습니다.");
        }
        return res.data.data.ciphertext;

    } catch (e) {
        console.error("[KMS Encrypt Error]", e.message);
        throw e;
    }
}

// 2. 복호화 함수
async function decryptKMS(cipherText) {
    if (!cipherText) return cipherText;
    const url = `/kms/v1/keys/${KMS_KEY_TAG}/decrypt`;
    const timestamp = Date.now().toString();
    const signature = makeSignature('POST', url, timestamp);
    try {
        const res = await axios.post(`https://ocapi.ncloud.com${url}`, { ciphertext: cipherText }, {
            headers: { 'x-ncp-apigw-timestamp': timestamp, 'x-ncp-iam-access-key': ACCESS_KEY, 'x-ncp-apigw-signature-v2': signature, 'Content-Type': 'application/json' }
        });
        const decrypted64 = res.data.data.plaintext;
        return Buffer.from(decrypted64, 'base64').toString('utf8');
    } catch (e) {
        console.error("[KMS Decrypt Error]", e.message);
        return cipherText;
    }
}

// 토큰 검증 미들웨어
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ msg: '토큰이 없습니다.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ msg: '유효하지 않은 토큰' });
        req.user = user; 
        next();
    });
}

// =================================================================
// API 라우트
// =================================================================

// 회원가입
app.post('/register', async (req, res) => {
    const { id, password, nickname, email } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.query('INSERT INTO users VALUES (?, ?, ?, ?, NOW())', [id, hashedPassword, nickname, email], (err) => {
            if (err) return res.status(400).json({ msg: '가입 실패' });
            res.json({ success: true });
        });
    } catch (e) { res.status(500).json({ msg: 'Error' }); }
});

// 로그인
app.post('/login', (req, res) => {
    const { id, password } = req.body;
    db.query('SELECT * FROM users WHERE id = ?', [id], async (err, results) => {
        if (err || results.length === 0) return res.status(401).json({ msg: '실패' });
        const match = await bcrypt.compare(password, results[0].password);
        if (!match) return res.status(401).json({ msg: '실패' });
        const token = jwt.sign({ id: results[0].id }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ success: true, token, nickname: results[0].nickname });
    });
});

// 인증번호 발송
app.post('/auth/send-code', (req, res) => {
    const { email } = req.body;
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const sql = `INSERT INTO email_verifications (email, code, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE)) ON DUPLICATE KEY UPDATE code=?, expires_at=DATE_ADD(NOW(), INTERVAL 5 MINUTE)`;
    db.query(sql, [email, code, code], (err) => {
        if (err) return res.status(500).json({ msg: 'DB Error' });
        transporter.sendMail({ from: GOOGLE_USER, to: email, subject: '인증번호', text: `인증번호: ${code}` }, () => {
            res.json({ success: true });
        });
    });
});

// 비밀번호 재설정
app.post('/auth/reset-pw', async (req, res) => {
    const { email, code, newPassword } = req.body;
    db.query('SELECT * FROM email_verifications WHERE email=? AND code=? AND expires_at > NOW()', [email, code], async (err, results) => {
        if (results.length === 0) return res.status(400).json({ msg: '인증번호 불일치' });
        const hashed = await bcrypt.hash(newPassword, 10);
        db.query('UPDATE users SET password=? WHERE email=?', [hashed, email], () => {
            res.json({ success: true });
        });
    });
});

// Presigned URL 발급
app.post('/presigned-url', (req, res) => {
    const { filename } = req.body;
    const params = { Bucket: 'my-board-bucket-2026', Key: filename, Expires: 60 };
    S3.getSignedUrl('putObject', params, (err, url) => {
        if(err) return res.status(500).json({error: "S3 Error"});
        res.json({ url });
    });
});

// ★ [수정됨] 게시글 쓰기 (작성자 ID 저장 추가)
app.post('/board', verifyToken, async (req, res) => {
    const { title, content, image_path } = req.body;
    const userId = req.user.id; // 토큰에서 추출한 사용자 ID

    let finalPath = image_path;
    if (image_path) {
        const filename = image_path.split('/').pop().split('?')[0];
        finalPath = `${GLOBAL_EDGE_URL}/${filename}`;
    }
    try {
        const encryptedContent = await encryptKMS(content);
        // user_id 컬럼에 현재 로그인한 사용자 ID 저장
        db.query('INSERT INTO boards (title, content, image_path, user_id, created_at) VALUES (?, ?, ?, ?, NOW())',
        [title, encryptedContent, finalPath, userId], (err) => {
            if(err) { console.error(err); return res.status(500).json({error: "DB Error"}); }
            res.json({ success: true });
        });
    } catch (e) {
        res.status(500).json({ error: "KMS Error" });
    }
});

// ★ [수정됨] 게시글 목록 조회 (닉네임 JOIN 및 시간 포맷팅)
app.get('/board', (req, res) => {
    // users 테이블과 조인하여 nickname 가져오기
    const sql = `
        SELECT b.id, b.title, b.content, b.image_path, b.created_at, b.user_id, u.nickname
        FROM boards b
        LEFT JOIN users u ON b.user_id = u.id
        ORDER BY b.created_at DESC
    `;

    db.query(sql, async (err, results) => {
        if(err) return res.status(500).json({error: "DB Error"});
        try {
            const decryptedResults = await Promise.all(results.map(async (row) => {
                const decryptedContent = await decryptKMS(row.content);
                // 한국 시간 포맷으로 변환
                const formattedTime = new Date(row.created_at).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' });
                
                return { 
                    ...row, 
                    content: decryptedContent,
                    created_at: formattedTime
                };
            }));
            res.json(decryptedResults);
        } catch (e) { res.status(500).json({ error: "Decryption Error" }); }
    });
});

// ★ [신규] 게시글 삭제 (본인 글 확인 로직 포함)
app.delete('/board/:id', verifyToken, (req, res) => {
    const boardId = req.params.id;
    const userId = req.user.id; // 요청한 사람 ID

    // 1. 글이 존재하고, 작성자가 맞는지 확인
    db.query('SELECT user_id FROM boards WHERE id = ?', [boardId], (err, results) => {
        if (err) return res.status(500).json({ msg: 'DB Error' });
        if (results.length === 0) return res.status(404).json({ msg: '글이 없습니다.' });

        const authorId = results[0].user_id;

        // 2. 작성자 검증 (DB의 작성자 vs 토큰의 요청자)
        if (authorId !== userId) {
            return res.status(403).json({ msg: '본인이 작성한 글만 삭제할 수 있습니다.' });
        }

        // 3. 삭제 수행
        db.query('DELETE FROM boards WHERE id = ?', [boardId], (err) => {
            if (err) return res.status(500).json({ msg: '삭제 실패' });
            res.json({ success: true, msg: '삭제되었습니다.' });
        });
    });
});

app.listen(3000, () => console.log('🚀 KMS Server Ready!'));
