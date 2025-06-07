# GamePlan

GamePlan is a web application for creating and joining events. Users can register, log in, create events, and join events.

## Features

- User registration and login
- Event creation and management
- Event joining and leaving
- User authentication with Passport.js
- MongoDB for data storage

## Tech Stack

- **Backend**: Node.js, Express.js, Mongoose, Passport.js, bcrypt
- **Frontend**: React, Axios
- **Database**: MongoDB
- **Hosting**: Vercel, Netlify, or Heroku

## Getting Started

### Prerequisites

- Node.js and npm installed
- MongoDB instance (local or cloud-based)

### Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/gameplan.git
cd gameplan
```

2. Install dependencies:

```bash
npm install
```

3. Set up environment variables:

Create a `.env` file in the backend directory with the following content:

```
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
SESSION_SECRET=your_session_secret
```

4. Start the application:

```bash
npm start
```

This will start both the backend and frontend servers.

## Folder Structure

- `backend/`: Backend code
- `frontend/`: Frontend code
- `backend/config/`: Configuration files
- `backend/controllers/`: Route controllers
- `backend/models/`: Mongoose models
- `backend/routes/`: Express routes
- `backend/middleware/`: Custom middleware

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the ISC License.
