const mongoose = require('mongoose');
const User = require('../models/User');
const { logger } = require('../utils/logger');

/**
 * Database migration script to add password reset fields to existing users
 * This script is safe to run multiple times and handles both development and production environments
 */

async function migratePasswordResetFields() {
  try {
    console.log('Starting password reset fields migration...');
    logger.info('Password reset migration started');

    // Connect to database if not already connected
    if (mongoose.connection.readyState === 0) {
      const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/gameplan';
      await mongoose.connect(mongoUri);
      console.log('Connected to MongoDB for migration');
    }

    // Count users that need migration (those without resetTokenUsed field)
    const usersNeedingMigration = await User.countDocuments({
      resetTokenUsed: { $exists: false }
    });

    console.log(`Found ${usersNeedingMigration} users that need migration`);

    if (usersNeedingMigration === 0) {
      console.log('No users need migration. All users already have password reset fields.');
      logger.info('Password reset migration completed - no users needed migration');
      return { success: true, migratedCount: 0, message: 'No migration needed' };
    }

    // Update users in batches to add default values for new fields
    const result = await User.updateMany(
      { resetTokenUsed: { $exists: false } },
      {
        $set: {
          resetTokenUsed: false
        },
        $unset: {
          resetToken: "",
          resetTokenExpiry: ""
        }
      }
    );

    console.log(`Migration completed successfully:`);
    console.log(`- Users updated: ${result.modifiedCount}`);
    console.log(`- Users matched: ${result.matchedCount}`);

    // Verify migration
    const remainingUsers = await User.countDocuments({
      resetTokenUsed: { $exists: false }
    });

    if (remainingUsers > 0) {
      throw new Error(`Migration incomplete: ${remainingUsers} users still need migration`);
    }

    // Create indexes if they don't exist
    console.log('Ensuring indexes exist...');
    await User.collection.createIndex({ resetToken: 1 }, { background: true, sparse: true });
    await User.collection.createIndex({ resetTokenExpiry: 1 }, { background: true, sparse: true });
    console.log('Indexes created successfully');

    logger.info('Password reset migration completed successfully', {
      migratedCount: result.modifiedCount,
      matchedCount: result.matchedCount
    });

    return {
      success: true,
      migratedCount: result.modifiedCount,
      matchedCount: result.matchedCount,
      message: 'Migration completed successfully'
    };

  } catch (error) {
    console.error('Migration failed:', error);
    logger.error('Password reset migration failed', {
      error: error.message,
      stack: error.stack
    });

    return {
      success: false,
      error: error.message,
      message: 'Migration failed'
    };
  }
}

/**
 * Rollback function to remove password reset fields (use with caution)
 */
async function rollbackPasswordResetFields() {
  try {
    console.log('Starting password reset fields rollback...');
    logger.warn('Password reset migration rollback started');

    const result = await User.updateMany(
      {},
      {
        $unset: {
          resetToken: "",
          resetTokenExpiry: "",
          resetTokenUsed: ""
        }
      }
    );

    console.log(`Rollback completed: ${result.modifiedCount} users updated`);
    logger.warn('Password reset migration rollback completed', {
      modifiedCount: result.modifiedCount
    });

    return {
      success: true,
      modifiedCount: result.modifiedCount,
      message: 'Rollback completed successfully'
    };

  } catch (error) {
    console.error('Rollback failed:', error);
    logger.error('Password reset migration rollback failed', {
      error: error.message,
      stack: error.stack
    });

    return {
      success: false,
      error: error.message,
      message: 'Rollback failed'
    };
  }
}

// Run migration if script is executed directly
if (require.main === module) {
  const command = process.argv[2];
  
  if (command === 'rollback') {
    rollbackPasswordResetFields()
      .then(result => {
        console.log('Rollback result:', result);
        process.exit(result.success ? 0 : 1);
      })
      .catch(error => {
        console.error('Rollback error:', error);
        process.exit(1);
      });
  } else {
    migratePasswordResetFields()
      .then(result => {
        console.log('Migration result:', result);
        process.exit(result.success ? 0 : 1);
      })
      .catch(error => {
        console.error('Migration error:', error);
        process.exit(1);
      });
  }
}

module.exports = {
  migratePasswordResetFields,
  rollbackPasswordResetFields
};
