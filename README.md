# auth-service

This is the authentication service microservice.

## Installation

To install and run this microservice locally, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/demok8s/auth-service.git
   ```

2. Navigate into the project directory:
   ```bash
   cd auth-service
   ```

3. Install dependencies:
   ```bash
   npm install
   ```

4. Set up environment variables:
   - Create a `.env` file in the root directory of the project.
   - Add the following environment variables to the `.env` file:
     ```plaintext
     MONGODB_URI=your_mongodb_connection_string
     JWT_SECRET=your_jwt_secret_key
     ```

5. Start the server:
   ```bash
   npm start
   ```

6. The server should now be running. You can access the endpoints at `http://localhost:3000`.

## Usage

- **Register a new user:** `POST /auth/register`
- **Log in with existing user:** `POST /auth/login`
- **Get user ID (protected route):** `GET /auth/user-id`
- **Check if user exists:** `POST /auth/check-user`
- **Reset user password:** `POST /auth/reset-password`

