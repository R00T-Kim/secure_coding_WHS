# Secure Coding Marketplace

> **Flask + SocketIO 기반 보안 강화를 최우선으로 설계한 중고거래 데모**  
> 최신 패치 (2025‑04‑17) 적용 버전

---

## ✨ 주요 기능
- **회원/인증** : 회원가입·로그인·로그아웃 (비밀번호 해시 저장)
- **상품** : 등록 · 목록 · 상세 (가격 숫자/범위 검증, 로그인 사용자만 등록)
- **프로필** : bio 수정 — `bleach` XSS 필터 적용
- **신고 기능** : 로그인 사용자만 가능
- **실시간 채팅** : 로그인 세션 검증, 메시지 300 자 제한 + XSS 필터
- **전역 보안 헤더** : CSP / X‑Frame‑Options / nosniff
- **CSRF 토큰** (경량) · **Secure 세션 쿠키** · **SQLite DB**

---

## ⚙️ 환경 설정

### 1) Conda 환경 생성
```bash
# 저장소 클론
git clone https://github.com/<YOUR_ID>/secure_coding_WHS.git
cd secure_coding_WHS

# Conda 환경 생성 & 활성화
conda env create -f environments.yaml     # => secure_coding_env
conda activate secure_coding_env
```

# environments.yaml 핵심 패키지 ↓

패키지 | 용도
flask 2.3.x | 웹 프레임워크
flask-socketio + eventlet | 실시간 채팅(WebSocket)
bleach | XSS 필터
(선택) flask-sqlalchemy | ORM 전환 대비

# 실행 방법
```bash
python3 app.py
```
