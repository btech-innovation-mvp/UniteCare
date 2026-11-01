# UniteCare Admin Web Application

The Admin Web Application is a Next.js (App Router) + TypeScript application designed for:
- System Administrators
- Community Administrators
- NGO Administrators

## Architectural Scope in Phase 0
- Authentication foundation (Email & Password login/logout)
- Protected route layout
- Administrative dashboard with genuine empty state ("No data available yet.")
- Zero fake user profiles or mock statistics

## Environment Variables
Copy `.env.example` to `.env.local`:
```bash
cp .env.example .env.local
```

| Variable | Description | Default |
| :--- | :--- | :--- |
| `NEXT_PUBLIC_API_URL` | Base URL for UniteCare Backend API | `http://localhost:8000/api/v1` |

## Setup Instructions (Stage 5)
Dependency installation and full application scaffolding will be performed in **Stage 5**.
