# NCP 3-Tier 고가용성 아키텍처 구축 & PoC

> 네이버클라우드(NCP) 위에 Web – WAS – DB 3계층 아키텍처를 직접 구성하고, 그 위에서 도는 커뮤니티 서비스를 구현한 PoC

## 구성

```
[Global Edge(CDN)] → [ALB(로드밸런서)] → [Web: Nginx] → [WAS: Node.js] → [DB: MySQL]
                                                          └→ [Object Storage] (이미지 업로드)
```

- **Web 계층** — Nginx 리버스 프록시 (`web-server/nginx.conf`), 정적 페이지 서빙
- **WAS 계층** — Node.js/Express (`was-server/server.js`): 게시판 글·사진 업로드 커뮤니티 API
- **인증** — 회원가입, **이메일 인증 기반 비밀번호 찾기**, **JWT** 세션
- **스토리지** — 업로드 이미지를 NCP **Object Storage**에 저장, CORS 설정 스크립트(`set_cors.js`) 포함
- **전송 최적화** — **Global Edge**(CDN)로 정적 자원 캐싱
- **가용성** — ALB 뒤에 서버를 두어 장애 시 트래픽 우회가 가능한 구조로 설계
- **배포 자동화** — GitHub Actions 워크플로우(`.github/workflows/main.yml`)로 배포 자동화 구성

## 만들면서 한 고민

클라우드 리소스를 콘솔에서 "되게만" 만드는 게 아니라, **각 계층이 왜 분리되는지**(스케일 아웃 단위, 장애 격리, 보안 경계)를 기준으로 배치했습니다. 시크릿은 코드에서 분리해 `.env`로 관리하고 저장소에는 `.env.example`만 커밋했습니다.

## 관련 자격

- NCA (Naver Cloud Associate), 2025.11
- DANCE 네이버 클라우드 아키텍트 양성과정 수료
