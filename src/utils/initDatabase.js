const mongoose = require('mongoose');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/gameplan', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// Import models
const User = require('../models/User');

// Function to initialize the database
async function initDatabase() {
  try {
    console.log('Starting database initialization...');

    // Ensure all collections are created
    await Promise.all([
      User.collection.createCollection(),
      // Add other collections as needed
    ]);

    console.log('Collections created successfully.');

    // Seed admin user
    let adminUser = await User.findOne({ email: 'SuperAdmin@gameplan.org' });
    if (!adminUser) {
      adminUser = new User({
        name: 'SuperAdmin',
        email: 'SuperAdmin@gameplan.org',
        password: 'P4ssw0rd123*', // Note: In a real application, you should hash the password
        isAdmin: true,
        isSuperAdmin: true,
        isProtected: true,
        isBlocked: false,
        gameNickname: 'SuperAdmin',
        status: 'approved',
        approvalNotes: 'Initial admin user',
        rejectedReason: '',
        registrationIP: '127.0.0.1',
        probationaryUntil: null,
        createdAt: new Date(),
        approvedAt: new Date(),
        approvedBy: null
      });
      await adminUser.save();
      console.log('Admin user seeded successfully.');
    } else {
      console.log('Admin user already exists.');
    }

    // Seed default user roles
    // Note: In a real application, you might want to create a separate Roles collection
    // For this example, we'll assume user roles are managed within the User model
    console.log('Default user roles already set in the User model.');

    console.log('Database initialization completed successfully.');
    process.exit(0);
  } catch (error) {
    console.error('Database initialization failed:', error);
    process.exit(1);
  }
}

// Run the initialization
initDatabase();
