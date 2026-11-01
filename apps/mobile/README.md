# UniteCare Mobile Field Application

The Mobile Application is an Expo / React Native (TypeScript) application designed for:
- Volunteers (following approved NGO affiliation)
- Social Workers
- Donors
- Other field operatives

## Architectural Scope in Phase 0
- Authentication foundation (Email & Password login/logout)
- Secure token persistence using `expo-secure-store`
- Android-first interface foundation
- Mobile dashboard with genuine empty state ("No data available yet.")
- Zero fake user profiles or mock statistics

## Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

| Variable | Description | Default |
| :--- | :--- | :--- |
| `EXPO_PUBLIC_API_URL` | Base URL for UniteCare Backend API | `http://10.0.2.2:8000/api/v1` (Android Emulator) |

> **Note for Android Testing**:
> - Android Emulator accesses host localhost at `http://10.0.2.2:8000/api/v1`.
> - Physical devices require host LAN IP (e.g., `http://192.168.x.x:8000/api/v1`).

## Setup Instructions (Stage 6)
Dependency installation and mobile client scaffolding will be performed in **Stage 6**.
