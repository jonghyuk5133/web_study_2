// server.js - Express 메인 서버
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = 3000;

// ─── 미들웨어 설정 ───────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 세션 설정
app.use(session({
    secret: 'my-super-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,   // JS에서 쿠키 접근 불가 (XSS 방어)
        maxAge: 1000 * 60 * 60 * 24  // 24시간
    }
}));


// ─── API 라우트 ──────────────────────────────────────────────────

// [POST] /api/register - 회원가입
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;

    // 입력값 검증
    if (!username || !password) {
        return res.status(400).json({ error: '아이디와 비밀번호를 입력해주세요.' });
    }
    if (username.length < 3 || username.length > 20) {
        return res.status(400).json({ error: '아이디는 3~20자여야 합니다.' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: '비밀번호는 6자 이상이어야 합니다.' });
    }

    // 아이디 중복 확인
    db.get('SELECT id FROM users WHERE username = ?', [username], async (err, row) => {
        if (err) return res.status(500).json({ error: 'DB 오류' });
        if (row) return res.status(409).json({ error: '이미 사용 중인 아이디입니다.' });

        // 비밀번호 해시화 (bcrypt, saltRounds=10)
        // 해시화: 원본 비밀번호를 복호화 불가능한 문자열로 변환
        const passwordHash = await bcrypt.hash(password, 10);

        db.run(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            [username, passwordHash],
            (err) => {
                if (err) return res.status(500).json({ error: 'DB 오류' });
                res.status(201).json({ message: '회원가입 성공!' });
            }
        );
    });
});


// [POST] /api/login - 로그인
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: '아이디와 비밀번호를 입력해주세요.' });
    }

    // DB에서 사용자 조회
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) return res.status(500).json({ error: 'DB 오류' });
        if (!user) return res.status(401).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' });

        // 비밀번호 검증 (입력값과 해시값 비교)
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(401).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' });

        // 세션에 사용자 정보 저장
        req.session.userId = user.id;
        req.session.username = user.username;

        res.json({ message: '로그인 성공!' });
    });
});


// [POST] /api/logout - 로그아웃
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).json({ error: '로그아웃 실패' });
        res.clearCookie('connect.sid');
        res.json({ message: '로그아웃 완료' });
    });
});


// [GET] /api/profile - 프로필 조회 (로그인 필요)
app.get('/api/profile', (req, res) => {
    // 세션에 userId가 없으면 미로그인 상태
    if (!req.session.userId) {
        return res.status(401).json({ error: '로그인이 필요합니다.' });
    }

    db.get(
        'SELECT id, username, created_at FROM users WHERE id = ?',
        [req.session.userId],
        (err, user) => {
            if (err) return res.status(500).json({ error: 'DB 오류' });
            if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });

            res.json({
                id: user.id,
                username: user.username,
                createdAt: user.created_at
            });
        }
    );
});


// ─── 서버 시작 ───────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`서버 실행 중: http://localhost:${PORT}`);
});
