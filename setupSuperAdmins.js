const mongoose = require('mongoose');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const User = require('./models/User');

async function setupSuperAdmins() {
  try {
    console.log('Setting up Super Admins...');
    
    // Check if Flamma user exists
    const flammaUser = await User.findOne({ email: 'flamma@gameplan.local' });
    if (flammaUser) {
      console.log('Found Flamma user, setting as protected super admin...');
      flammaUser.isAdmin = true;
      flammaUser.isSuperAdmin = true;
      flammaUser.isProtected = true;
      await flammaUser.save();
      console.log('✅ Flamma set as protected super admin');
    } else {
      console.log('⚠️  Flamma user not found, skipping...');
    }
    
    // Check if DevAdmin user exists (for development)
    const devAdminUser = await User.findOne({ email: 'dev-admin@gameplan.local' });
    if (devAdminUser) {
      console.log('Found DevAdmin user, setting as super admin...');
      devAdminUser.isAdmin = true;
      devAdminUser.isSuperAdmin = true;
      devAdminUser.isProtected = false;
      await devAdminUser.save();
      console.log('✅ DevAdmin set as super admin');
    } else {
      console.log('⚠️  DevAdmin user not found, skipping...');
    }
    
    // Find any existing admin users and show their status
    const adminUsers = await User.find({ isAdmin: true });
    console.log('\n📊 Current Admin Status:');
    console.log('========================');
    
    for (const user of adminUsers) {
      const badges = [];
      if (user.isSuperAdmin) badges.push('SUPER ADMIN');
      if (user.isProtected) badges.push('PROTECTED');
      if (user.isAdmin && !user.isSuperAdmin) badges.push('ADMIN');
      
      console.log(`${user.email} - ${badges.join(', ')}`);
    }
    
    console.log('\n✅ Super Admin setup complete!');
    console.log('\nSuper Admin Privileges:');
    console.log('- Can promote/demote admins');
    console.log('- Can promote users to super admin');
    console.log('- Can demote super admins (except protected users)');
    console.log('- Can delete/block/modify admin users');
    console.log('- Cannot delete super admins directly (must demote first)');
    console.log('\nProtected User Rules (Flamma):');
    console.log('- Cannot be deleted by anyone');
    console.log('- Cannot be modified by anyone except themselves');
    console.log('- Always remains protected super admin');
    
  } catch (error) {
    console.error('❌ Error setting up super admins:', error);
  } finally {
    mongoose.connection.close();
  }
}

setupSuperAdmins();
