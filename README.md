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

### Prerequisites

- Node.js
- MongoDB (local or MongoDB Atlas) for development

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

3. Create a `.env` file in the root directory and add your environment variables:
   ```
   PORT=3000
   MONGO_URI=mongodb://localhost:27017/gameplan  # For local MongoDB
   # OR
   # MONGO_URI=mongodb+srv://<username>:<password>@cluster0.mongodb.net/gameplan?retryWrites=true&w=majority  # For MongoDB Atlas
   SESSION_SECRET=your_secret_key
   ```

4. Start the server:
   ```bash
   npm run dev
   ```

5. Open your browser and navigate to `http://localhost:3000`.

### Using MongoDB Atlas

1. Sign up for a free MongoDB Atlas account at [MongoDB Atlas](https://www.mongodb.com/cloud/atlas).
2. Create a new cluster.
3. Create a new database user with read/write access.
4. Whitelist your IP address to allow connections to the cluster.
5. Get the connection string for your cluster from the Atlas dashboard.
6. Replace `<username>` and `<password>` in the `.env` file with your MongoDB Atlas username and password.

## Deployment

### Render.com

1. Create a new web service on Render.com.
2. Connect your GitHub repository.
3. Set the environment variables in the Render dashboard:
   - `PORT`: The port number (e.g., 3000)
   - `MONGO_URI`: Your MongoDB connection string
   - `SESSION_SECRET`: A secret key for session management

4. Deploy the application.

## Contributing

Feel free to submit issues, fork the repository, and send pull requests!

## License

This project is licensed under the ISC License.
