// MongoDB initialization script for GamePlan
// This script creates the application database and user

// Switch to the gameplan database
db = db.getSiblingDB('gameplan');

// Create the application user with read/write permissions
db.createUser({
  user: 'gameplan_user',
  pwd: process.env.MONGO_PASSWORD || 'gameplan_password',
  roles: [
    {
      role: 'readWrite',
      db: 'gameplan'
    }
  ]
});

// Create initial collections with indexes for better performance
db.createCollection('users');
db.createCollection('events');
db.createCollection('games');
db.createCollection('extensions');
db.createCollection('auditlogs');
db.createCollection('rejectedemails');

// Create indexes for better performance
db.users.createIndex({ email: 1 }, { unique: true });
db.users.createIndex({ status: 1 });
db.users.createIndex({ createdAt: 1 });
db.users.createIndex({ registrationIP: 1 });

db.events.createIndex({ date: 1 });
db.events.createIndex({ createdBy: 1 });
db.events.createIndex({ game: 1 });
db.events.createIndex({ isVisible: 1 });
db.events.createIndex({ gameStatus: 1 });

db.games.createIndex({ name: 1 });
db.games.createIndex({ status: 1 });
db.games.createIndex({ source: 1 });
db.games.createIndex({ steamAppId: 1 }, { sparse: true });
db.games.createIndex({ rawgId: 1 }, { sparse: true });

db.auditlogs.createIndex({ timestamp: -1 });
db.auditlogs.createIndex({ adminId: 1 });
db.auditlogs.createIndex({ action: 1 });

db.rejectedemails.createIndex({ email: 1 }, { unique: true });

print('GamePlan database initialized successfully');
