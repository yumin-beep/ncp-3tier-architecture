const AWS = require('aws-sdk');

const endpoint = new AWS.Endpoint('https://kr.object.ncloudstorage.com');
const region = 'kr-standard';

// ★ 선생님의 NCP Access Key 정보 입력 (server.js에 있는 것과 동일)
const access_key = '여기에_액세스키_입력';
const secret_key = '여기에_시크릿키_입력';

const S3 = new AWS.S3({
    endpoint: endpoint,
    region: region,
    credentials: {
        accessKeyId: access_key,
        secretAccessKey: secret_key
    }
});

const bucket_name = 'my-board-bucket-2026'; // ★ 선생님 버킷 이름 확인!

const corsParams = {
    Bucket: bucket_name,
    CORSConfiguration: {
        CORSRules: [
            {
                // 브라우저가 업로드(PUT) 할 수 있게 허용
                AllowedHeaders: ["*"],
                AllowedMethods: ["GET", "PUT", "POST", "HEAD", "DELETE"],
                AllowedOrigins: ["*"], // 모든 사이트 허용 (테스트용)
                ExposeHeaders: ["ETag"],
                MaxAgeSeconds: 3000
            }
        ]
    }
};

async function setCORS() {
    try {
        await S3.putBucketCors(corsParams).promise();
        console.log("✅ CORS 설정이 성공적으로 적용되었습니다!");
        
        // 확인 사살
        const check = await S3.getBucketCors({ Bucket: bucket_name }).promise();
        console.log("확인된 설정:", JSON.stringify(check, null, 2));
    } catch (e) {
        console.error("❌ 설정 실패:", e);
    }
}

setCORS();
