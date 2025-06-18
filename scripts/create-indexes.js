#!/usr/bin/env node

/**
 * GamePlan Database Index Creation Script
 * 
 * This script creates optimized indexes for the GamePlan application
 * to improve query performance across User, Event, and Game collections.
 * 
 * Usage:
 *   node scripts/create-indexes.js
 * 
 * Or via MongoDB shell:
 *   mongosh gameplan scripts/create-indexes.js
 */

const { MongoClient } = require('mongodb');
require('dotenv').config();

// Database connection configuration
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/gameplan';
const DB_NAME = 'gameplan';

// Index definitions organized by collection
const INDEX_DEFINITIONS = {
  users: [
    // Compound indexes for admin user management
    { keys: { status: 1, createdAt: -1 }, name: 'status_createdAt', background: true },
    { keys: { isAdmin: 1, status: 1 }, name: 'isAdmin_status', background: true },
    { keys: { isBlocked: 1, status: 1 }, name: 'isBlocked_status', background: true },
    
    // Probationary user queries
    { keys: { probationaryUntil: 1 }, name: 'probationaryUntil', background: true, sparse: true },
    
    // Enhanced search capabilities
    { keys: { name: 'text', email: 'text', gameNickname: 'text' }, name: 'user_text_search', background: true },
    
    // IP-based security analysis
    { keys: { registrationIP: 1, createdAt: -1 }, name: 'registrationIP_createdAt', background: true },
    
    // Complex admin dashboard queries
    { keys: { status: 1, isAdmin: 1, createdAt: -1 }, name: 'status_isAdmin_createdAt', background: true },
    
    // Approval workflow optimization
    { keys: { status: 1, approvedAt: -1 }, name: 'status_approvedAt', background: true, sparse: true }
  ],

  events: [
    // Main event listing optimizations
    { keys: { isVisible: 1, date: 1 }, name: 'isVisible_date', background: true },
    { keys: { gameStatus: 1, date: 1 }, name: 'gameStatus_date', background: true },
    
    // Admin event management
    { keys: { date: -1, gameStatus: 1 }, name: 'date_gameStatus', background: true },
    { keys: { createdBy: 1, date: -1 }, name: 'createdBy_date', background: true },
    
    // Game-specific event queries
    { keys: { game: 1, date: 1 }, name: 'game_date', background: true },
    { keys: { game: 1, isVisible: 1 }, name: 'game_isVisible', background: true },
    
    // Event search functionality
    { keys: { name: 'text', description: 'text' }, name: 'event_text_search', background: true },
    
    // Complex visibility and status queries
    { keys: { isVisible: 1, gameStatus: 1, date: 1 }, name: 'isVisible_gameStatus_date', background: true },
    
    // Player management queries
    { keys: { players: 1, date: 1 }, name: 'players_date', background: true },
    
    // Date range queries for admin dashboard
    { keys: { createdAt: -1, gameStatus: 1 }, name: 'createdAt_gameStatus', background: true }
  ],

  games: [
    // Game approval workflow
    { keys: { status: 1, createdAt: -1 }, name: 'status_createdAt', background: true },
    { keys: { status: 1, source: 1 }, name: 'status_source', background: true },
    
    // Enhanced search capabilities
    { keys: { name: 'text' }, name: 'game_text_search', background: true },
    
    // Steam/RAWG integration optimization
    { keys: { source: 1, steamAppId: 1 }, name: 'source_steamAppId', background: true, sparse: true },
    { keys: { source: 1, rawgId: 1 }, name: 'source_rawgId', background: true, sparse: true },
    
    // Admin game management
    { keys: { addedBy: 1, createdAt: -1 }, name: 'addedBy_createdAt', background: true, sparse: true },
    
    // Complex approval queries
    { keys: { status: 1, source: 1, createdAt: -1 }, name: 'status_source_createdAt', background: true },
    
    // Duplicate detection optimization
    { keys: { name: 1, source: 1 }, name: 'name_source', background: true },
    
    // Category and platform filtering
    { keys: { categories: 1, status: 1 }, name: 'categories_status', background: true },
    { keys: { platforms: 1, status: 1 }, name: 'platforms_status', background: true }
  ],

  auditlogs: [
    // Enhanced audit log queries
    { keys: { timestamp: -1, action: 1 }, name: 'timestamp_action', background: true },
    { keys: { adminId: 1, timestamp: -1 }, name: 'adminId_timestamp', background: true },
    { keys: { targetUserId: 1, timestamp: -1 }, name: 'targetUserId_timestamp', background: true, sparse: true },
    
    // Bulk operation analysis
    { keys: { action: 1, bulkCount: 1, timestamp: -1 }, name: 'action_bulkCount_timestamp', background: true }
  ],

  errorlogs: [
    // Error log analysis and management
    { keys: { timestamp: -1, 'resolution.status': 1 }, name: 'timestamp_resolutionStatus', background: true },
    { keys: { 'analytics.severity': 1, timestamp: -1 }, name: 'severity_timestamp', background: true },
    { keys: { errorType: 1, statusCode: 1, timestamp: -1 }, name: 'errorType_statusCode_timestamp', background: true },
    { keys: { 'analytics.severity': 1, 'resolution.status': 1, timestamp: -1 }, name: 'severity_status_timestamp', background: true },
    
    // User and IP analysis
    { keys: { 'userContext.email': 1, timestamp: -1 }, name: 'userEmail_timestamp', background: true, sparse: true },
    { keys: { 'requestContext.ip': 1, timestamp: -1 }, name: 'requestIP_timestamp', background: true }
  ]
};

/**
 * Create indexes for a specific collection
 */
async function createCollectionIndexes(db, collectionName, indexes) {
  console.log(`\n📊 Creating indexes for ${collectionName} collection...`);
  
  const collection = db.collection(collectionName);
  let created = 0;
  let skipped = 0;
  let errors = 0;

  for (const indexDef of indexes) {
    try {
      const indexName = indexDef.name;
      
      // Check if index already exists
      const existingIndexes = await collection.listIndexes().toArray();
      const indexExists = existingIndexes.some(idx => idx.name === indexName);
      
      if (indexExists) {
        console.log(`  ⏭️  Index '${indexName}' already exists, skipping`);
        skipped++;
        continue;
      }

      // Create the index
      const options = {
        name: indexName,
        background: indexDef.background || true
      };
      
      if (indexDef.sparse) options.sparse = true;
      if (indexDef.unique) options.unique = true;

      await collection.createIndex(indexDef.keys, options);
      console.log(`  ✅ Created index '${indexName}'`);
      created++;
      
    } catch (error) {
      console.error(`  ❌ Failed to create index '${indexDef.name}': ${error.message}`);
      errors++;
    }
  }

  console.log(`  📈 Summary: ${created} created, ${skipped} skipped, ${errors} errors`);
  return { created, skipped, errors };
}

/**
 * Main execution function
 */
async function createIndexes() {
  let client;
  
  try {
    console.log('🚀 GamePlan Database Index Creation Starting...');
    console.log(`📍 Connecting to: ${MONGO_URI.replace(/\/\/.*@/, '//***:***@')}`);
    
    // Connect to MongoDB
    client = new MongoClient(MONGO_URI);
    await client.connect();
    
    const db = client.db(DB_NAME);
    
    // Verify database connection
    await db.admin().ping();
    console.log('✅ Database connection established');
    
    // Track overall statistics
    let totalCreated = 0;
    let totalSkipped = 0;
    let totalErrors = 0;
    
    // Create indexes for each collection
    for (const [collectionName, indexes] of Object.entries(INDEX_DEFINITIONS)) {
      const stats = await createCollectionIndexes(db, collectionName, indexes);
      totalCreated += stats.created;
      totalSkipped += stats.skipped;
      totalErrors += stats.errors;
    }
    
    // Final summary
    console.log('\n🎉 Index Creation Complete!');
    console.log('📊 Overall Summary:');
    console.log(`  ✅ Total Created: ${totalCreated}`);
    console.log(`  ⏭️  Total Skipped: ${totalSkipped}`);
    console.log(`  ❌ Total Errors: ${totalErrors}`);
    
    if (totalErrors === 0) {
      console.log('\n🚀 All indexes created successfully!');
      console.log('💡 Your database queries should now be significantly faster.');
      console.log('📈 Run the verify-indexes.js script to test performance improvements.');
    } else {
      console.log(`\n⚠️  ${totalErrors} errors occurred. Please review the error messages above.`);
    }
    
  } catch (error) {
    console.error('💥 Fatal error during index creation:', error.message);
    console.error('🔍 Full error:', error);
    process.exit(1);
    
  } finally {
    if (client) {
      await client.close();
      console.log('🔌 Database connection closed');
    }
  }
}

// Execute if run directly
if (require.main === module) {
  createIndexes().catch(console.error);
}

module.exports = { createIndexes, INDEX_DEFINITIONS };
