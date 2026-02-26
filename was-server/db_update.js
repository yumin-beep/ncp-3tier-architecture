require('dotenv').config();
const mysql = require('mysql2');

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

console.log("DB 접속 시도 중...");

// 컬럼 추가 명령 실행
db.query('ALTER TABLE boards ADD COLUMN user_id VARCHAR(50)', (err, result) => {
    if (err) {
        // 이미 컬럼이 있으면 에러가 날 수 있음 (무시 가능)
        console.log("⚠️ 알림:", err.code); 
        console.log("메시지:", err.sqlMessage);
    } else {
        console.log("✅ 성공! boards 테이블에 user_id 컬럼이 추가되었습니다.");
    }
    db.end(); // 접속 종료
});
