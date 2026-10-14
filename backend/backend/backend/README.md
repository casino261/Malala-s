NaijaPlay Backend

The backend API for the NaijaPlay website.

Requirements

* Node.js 20 or newer
* npm

Install dependencies

Run this command inside the backend directory:

npm install

Start the server

Run:

npm start

The server uses the PORT environment variable, or port 3000 by default.

Health Check

After deployment, visit:

https://YOUR-BACKEND-DOMAIN/api/health

A successful response should show:

{"status":"healthy","service":"NaijaPlay API"}

Environment Variables

Configure environment variables through your backend hosting provider. Never upload passwords, payment credentials, or API secrets to GitHub.

Production Status

This is an initial backend foundation. User accounts, database storage, payment integration, withdrawals, game-provider integration, monitoring, and production security checks still need to be implemented and tested before real-money transactions are enabled.
