# Where Backend

Where 프론트엔드에서 사용하는 독립형 Node.js API 서버입니다. PostgreSQL 회원 정보, Google 로그인, 친구/관계 알림, 카카오 장소 검색과 자동차 경로 조회를 제공합니다.

## 로컬 실행

Node.js 20 이상과 PostgreSQL 데이터베이스가 필요합니다.

```bash
git clone https://github.com/kimgeon5023/Where-Backend.git
cd Where-Backend
npm install
cp .env.example .env
npm run dev
```

Windows PowerShell에서는 환경 파일을 다음처럼 복사할 수 있습니다.

```powershell
Copy-Item .env.example .env
```

`.env`의 `DATABASE_URL`을 먼저 설정하세요. 서버가 시작될 때 필요한 테이블과 인덱스를 자동으로 생성합니다. 실제 비밀번호와 API 키가 들어간 `.env`는 Git에 커밋하지 마세요.

정상 실행 여부는 `http://localhost:3001/api/health`에서 확인할 수 있습니다.

## 프론트엔드 연결

Vite 프론트엔드의 `.env`에 API 서버 주소를 넣습니다.

```env
VITE_API_BASE_URL=http://localhost:3001
```

배포 환경에서는 Render 주소를 사용합니다.

```env
VITE_API_BASE_URL=https://where-api-kimgeon5023.onrender.com
```

API 호출은 `${VITE_API_BASE_URL}/api/...` 형태로 구성하면 됩니다. 현재 Where 프론트의 `src/lib/api.ts`를 그대로 사용할 수 있습니다.

## 주요 API

- `GET /api/health`
- `GET /api/places`
- `POST /api/route`
- `POST /api/auth/signup`
- `POST /api/auth/login`
- `GET /api/auth/oauth/google`
- `PUT /api/auth/password`
- `PUT /api/auth/users/:id`
- `DELETE /api/auth/users/:id`
- `GET /api/social/users`
- `GET /api/social/friends`
- `POST /api/social/friends`
- `GET /api/social/notifications`
- `POST /api/social/relationship-requests`

## Google 로그인

Google Cloud Console의 승인된 리디렉션 URI에 아래 주소를 등록합니다.

```text
http://localhost:3001/api/auth/oauth/google/callback
https://YOUR_RENDER_DOMAIN/api/auth/oauth/google/callback
```

백엔드의 `FRONTEND_URL`은 로그인 완료 후 돌아갈 프론트 주소, `API_BASE_URL`은 외부에서 접근 가능한 백엔드 주소로 설정하세요.

## Render 배포

저장소 루트의 `render.yaml`을 Blueprint로 사용하거나 Web Service를 직접 만들 수 있습니다.

- Build command: `npm ci`
- Start command: `npm start`
- Health check: `/api/health`

필요한 환경변수 이름은 `.env.example`과 `render.yaml`에 정리되어 있습니다.
