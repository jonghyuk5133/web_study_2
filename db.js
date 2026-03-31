// db.js - SQLite 데이터베이스 초기화
// sqlite3는 비동기(콜백) 방식 API를 사용함

const sqlite3 = require('sqlite3').verbose();

// db.sqlite 파일이 없으면 자동으로 생성됨
const db = new sqlite3.Database('db.sqlite', (err) => {
    if (err) {
        console.error('DB 연결 실패:', err.message);
    } else {
        console.log('DB 연결 성공');
    }
});

// users 테이블 생성 (없으면 생성, 있으면 그냥 넘어감)
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
  )
`, (err) => {
    if (err) {
        console.error('테이블 생성 실패:', err.message);
    } else {
        console.log('users 테이블 준비 완료');
    }
});

module.exports = db;
