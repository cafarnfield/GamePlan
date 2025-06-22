const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// Import models
const User = require('../models/User');

async function initializeAdmin() {
  try {
    console.log('Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('Connected to MongoDB successfully');

    // Check if admin user already exists
    const adminEmail = process.env.ADMIN_EMAIL;
    if (!adminEmail) {
      console.error('ADMIN_EMAIL environment variable is required');
      process.exit(1);
    }

    const existingAdmin = await User.findOne({ email: adminEmail.toLowerCase() });
    if (existingAdmin) {
      console.log(`Admin user with email ${adminEmail} already exists`);
      
      // Update admin privileges if not already set
      if (!existingAdmin.isAdmin || !existingAdmin.isSuperAdmin) {
        existingAdmin.isAdmin = true;
        existingAdmin.isSuperAdmin = true;
        existingAdmin.status = 'approved';
        existingAdmin.isProtected = true;
        await existingAdmin.save();
        console.log('Updated existing user with admin privileges');
      }
      
      process.exit(0);
    }

    // Create new admin user
    const adminPassword = process.env.ADMIN_PASSWORD;
    if (!adminPassword) {
      console.error('ADMIN_PASSWORD environment variable is required');
      process.exit(1);
    }

    const hashedPassword = await bcrypt.hash(adminPassword, 10);
    
    const adminUser = new User({
      name: process.env.ADMIN_NAME || 'GamePlan Administrator',
      email: adminEmail.toLowerCase(),
      password: hashedPassword,
      gameNickname: process.env.ADMIN_NICKNAME || 'Admin',
      isAdmin: true,
      isSuperAdmin: true,
      status: 'approved',
      isProtected: true,
      approvedAt: new Date(),
      createdAt: new Date()
    });

    await adminUser.save();
    console.log(`Admin user created successfully with email: ${adminEmail}`);
    console.log('Admin user has been granted Super Admin privileges');
    
  } catch (error) {
    console.error('Error initializing admin user:', error);
    process.exit(1);
  } finally {
    await mongoose.connection.close();
    console.log('Database connection closed');
  }
}

// Run the initialization
initializeAdmin();
