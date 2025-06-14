# GamePlan

GamePlan is a simple web application that allows users to register, log in, create events, and join events.

## Features

- User registration and login
- Event creation
- View all events
- Join/leave events
- Event details page

## Technologies Used

- Node.js
- Express.js
- MongoDB (using Mongoose)
- EJS (Embedded JavaScript templates)
- Passport.js (for authentication)
- bcrypt (for password hashing)
- body-parser (for parsing request bodies)

## Project Structure

```
GamePlan/
├── config/
├── models/
├── public/
├── routes/
├── views/
├── app.js
├── package.json
└── README.md
```

## Setup Instructions

### Docker Deployment (Recommended)

The easiest way to deploy GamePlan is using Docker Compose:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/cafarnfield/GamePlan.git
   cd GamePlan
   ```

2. **Configure environment:**
   ```bash
   cp .env.example .env
   nano .env  # Edit with your settings
   ```

3. **Start the application:**
   ```bash
   docker-compose up -d
   ```

4. **Initialize admin user:**
   ```bash
   docker-compose --profile init up init-admin
   ```

5. **Access the application:**
   - Main application: `http://localhost:3000`
   - Database admin: `http://localhost:8081` (optional)

For detailed Docker deployment instructions, see [DEPLOYMENT.md](DEPLOYMENT.md).

### Manual Installation (Development)

#### Prerequisites

- Node.js (18 or later)
- MongoDB (local or MongoDB Atlas)

#### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/cafarnfield/GamePlan.git
   cd GamePlan
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a `.env` file in the root directory and add your environment variables:
   ```
   PORT=3000
   MONGO_URI=mongodb://localhost:27017/gameplan  # For local MongoDB
   # OR
   # MONGO_URI=mongodb+srv://<username>:<password>@cluster0.mongodb.net/gameplan?retryWrites=true&w=majority  # For MongoDB Atlas
   SESSION_SECRET=your_secret_key
   STEAM_API_KEY=your_steam_api_key
   RAWG_API_KEY=3963501b74354e0688413453cb8c6bc4
   ```

4. Start the server:
   ```bash
   npm run dev
   ```

5. Open your browser and navigate to `http://localhost:3000`.

#### Using MongoDB Atlas

1. Sign up for a free MongoDB Atlas account at [MongoDB Atlas](https://www.mongodb.com/cloud/atlas).
2. Create a new cluster.
3. Create a new database user with read/write access.
4. Whitelist your IP address to allow connections to the cluster.
5. Get the connection string for your cluster from the Atlas dashboard.
6. Replace `<username>` and `<password>` in the `.env` file with your MongoDB Atlas username and password.

## Deployment

### Docker (Recommended)

See [DEPLOYMENT.md](DEPLOYMENT.md) for comprehensive Docker deployment instructions.

### Traditional Hosting

#### Render.com

1. Create a new web service on Render.com.
2. Connect your GitHub repository.
3. Set the environment variables in the Render dashboard:
   - `PORT`: The port number (e.g., 3000)
   - `MONGO_URI`: Your MongoDB connection string
   - `SESSION_SECRET`: A secret key for session management
   - `STEAM_API_KEY`: Your Steam API key (optional)
   - `RAWG_API_KEY`: Your RAWG API key

4. Deploy the application.

## Contributing

Feel free to submit issues, fork the repository, and send pull requests!

## License

This project is licensed under the ISC License.
