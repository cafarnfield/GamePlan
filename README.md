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

### Ubuntu Server Deployment (One-Click Install)

For Ubuntu Server users, we provide a complete automated installation:

**Quick Install:**
```bash
curl -fsSL https://raw.githubusercontent.com/cafarnfield/GamePlan/main/scripts/ubuntu-install.sh | bash
```

**Manual Install:**
```bash
git clone https://github.com/cafarnfield/GamePlan.git
cd GamePlan
chmod +x scripts/ubuntu-install.sh
./scripts/ubuntu-install.sh
```

This script automatically:
- ✅ Installs Docker and Docker Compose
- ✅ Configures system requirements
- ✅ Sets up secure passwords
- ✅ Configures firewall (UFW)
- ✅ Creates systemd service for auto-start
- ✅ Deploys and initializes GamePlan

For complete Ubuntu deployment guide with SSL setup, see [UBUNTU_DEPLOYMENT.md](UBUNTU_DEPLOYMENT.md).

### Debian Server Deployment (One-Click Install)

For Debian Server users, we provide a complete automated installation:

**Quick Install:**
```bash
curl -fsSL https://raw.githubusercontent.com/cafarnfield/GamePlan/main/scripts/debian-install.sh | bash
```

**Manual Install:**
```bash
git clone https://github.com/cafarnfield/GamePlan.git
cd GamePlan
chmod +x scripts/debian-install.sh
./scripts/debian-install.sh
```

This script automatically:
- ✅ Installs Docker and Docker Compose
- ✅ Configures system requirements
- ✅ Sets up secure passwords
- ✅ Configures firewall (UFW)
- ✅ Creates systemd service for auto-start
- ✅ Deploys and initializes GamePlan
- ✅ Handles Docker permission setup

For complete Debian deployment guide with SSL setup, see [DEBIAN_DEPLOYMENT.md](DEBIAN_DEPLOYMENT.md).

### Local Development (Recommended for Development)

GamePlan includes a comprehensive local development system with automatic setup, backup, and reset capabilities.

#### Prerequisites

- Docker Desktop (with Docker Compose)
- Git

#### Quick Start

**Windows (PowerShell):**
```powershell
.\setup-local.ps1
```

**Linux/Mac (Bash):**
```bash
./setup-local.sh
```

This one-command setup will:
- ✅ Check Docker availability
- ✅ Create optimized local configuration
- ✅ Install dependencies
- ✅ Build and start all services
- ✅ Initialize admin user
- ✅ Show access URLs

#### Access Points

After setup:
- **Main Application**: http://localhost:3000
- **Database Admin**: http://localhost:8081
- **API Health**: http://localhost:3000/api/health

#### Development Features

- 🔄 **Hot Reload**: Code changes automatically restart the app
- 🐛 **Debug Mode**: Verbose logging and debug port (9229) exposed
- 🗄️ **Auto Backup**: Built-in backup and restore system
- 🔧 **Easy Reset**: One-command environment reset
- 📊 **Database UI**: Mongo Express for database management

#### Development Commands

```bash
# Backup your work
./backup-local.sh        # Linux/Mac
.\backup-local.ps1       # Windows

# Reset environment
./reset-local.sh         # Linux/Mac
.\reset-local.ps1        # Windows

# View logs
docker compose logs -f

# Stop services
docker compose down
```

For complete local development guide, see [LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md).

### Manual Installation (Advanced)

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
   RAWG_API_KEY=3963501b74354e0688413453cb8c6bc4
   
   # Note: Steam integration works automatically without requiring an API key
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

### Safe Deployment Updates (RECOMMENDED)

For existing deployments, use the new safe deployment scripts to update without killing your app:

**Linux/Unix Server:**
```bash
cd /path/to/GamePlan
chmod +x safe-deploy-update.sh
./safe-deploy-update.sh
```

**Windows Development:**
```cmd
safe-deploy-update.bat
```

**Safe Deployment Features:**
- ✅ Uses `git merge` instead of destructive `git reset --hard`
- ✅ Backs up production configurations automatically
- ✅ Only restarts services when code changes require it
- ✅ Comprehensive health verification with automatic rollback
- ✅ Preserves local changes and server-specific files

See [SAFE_DEPLOYMENT_GUIDE.md](SAFE_DEPLOYMENT_GUIDE.md) for complete safe deployment documentation.

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
   - `RAWG_API_KEY`: Your RAWG API key

4. Deploy the application.

## Contributing

Feel free to submit issues, fork the repository, and send pull requests!

## License

This project is licensed under the ISC License.
