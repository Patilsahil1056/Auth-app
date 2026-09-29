# auth-app: JWT + Session authentication

Node.js, Express, MongoDB Atlas, JWT and express-session.

## Setup
1. `npm install`
2. Edit `.env` and set your real `MONGO_URI` (Atlas), `JWT_SECRET` and `SESSION_SECRET`.
3. `npm start` and open http://localhost:3000

## Routes
- GET/POST `/register`
- GET/POST `/login`
- GET `/dashboard` (protected: needs a valid JWT cookie and an active session)
- POST `/logout` (destroys the session and clears the JWT cookie)
