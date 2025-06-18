#!/usr/bin/env node

/**
 * GamePlan Database Index Verification Script
 * 
 * This script verifies that indexes are properly created and tests
 * their performance impact on common queries.
 * 
 * Usage:
 *   node scripts/verify-indexes.js
 */

const { MongoClient, ObjectId } = require('mongodb');
require('dotenv').config();

// Database connection configuration
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/gameplan';
const DB_NAME = 'gameplan';

/**
 * Test queries that should benefit from the new indexes
 */
const TEST_QUERIES = {
  users: [
    {
      name: 'Admin User Management - Status Filter',
      query: { status: 'pending' },
      sort: { createdAt: -1 },
      expectedIndex: 'status_createdAt'
    },
    {
      name: 'Admin Dashboard - Admin Users',
      query: { isAdmin: true, status: 'approved' },
      expectedIndex: 'isAdmin_status'
    },
    {
      name: 'Security Analysis - IP Registration',
      query: { registrationIP: '192.168.1.1' },
      sort: { createdAt: -1 },
      expectedIndex: 'registrationIP_createdAt'
    },
    {
      name: 'Probationary Users',
      query: { probationaryUntil: { $gte: new Date() } },
      expectedIndex: 'probationaryUntil'
    },
    {
      name: 'User Text Search',
      query: { $text: { $search: 'john' } },
      expectedIndex: 'user_text_search'
    }
  ],

  events: [
    {
      name: 'Main Event Listing - Visible Events',
      query: { isVisible: true },
      sort: { date: 1 },
      expectedIndex: 'isVisible_date'
    },
    {
      name: 'Admin Event Management - Pending Games',
      query: { gameStatus: 'pending' },
      sort: { date: 1 },
      expectedIndex: 'gameStatus_date'
    },
    {
      name: 'User Events - Created By User',
      query: { createdBy: new ObjectId() },
      sort: { date: -1 },
      expectedIndex: 'createdBy_date'
    },
    {
      name: 'Game Events - Events for Specific Game',
      query: { game: new ObjectId(), isVisible: true },
      expectedIndex: 'game_isVisible'
    },
    {
      name: 'Event Text Search',
      query: { $text: { $search: 'tournament' } },
      expectedIndex: 'event_text_search'
    },
    {
      name: 'Complex Visibility Query',
      query: { isVisible: true, gameStatus: 'approved' },
      sort: { date: 1 },
      expectedIndex: 'isVisible_gameStatus_date'
    }
  ],

  games: [
    {
      name: 'Game Approval Workflow',
      query: { status: 'pending' },
      sort: { createdAt: -1 },
      expectedIndex: 'status_createdAt'
    },
    {
      name: 'Steam Games Filter',
      query: { status: 'approved', source: 'steam' },
      expectedIndex: 'status_source'
    },
    {
      name: 'Game Text Search',
      query: { $text: { $search: 'minecraft' } },
      expectedIndex: 'game_text_search'
    },
    {
      name: 'Steam Integration Lookup',
      query: { source: 'steam', steamAppId: { $exists: true } },
      expectedIndex: 'source_steamAppId'
    },
    {
      name: 'Admin Added Games',
      query: { addedBy: new ObjectId() },
      sort: { createdAt: -1 },
      expectedIndex: 'addedBy_createdAt'
    }
  ],

  auditlogs: [
    {
      name: 'Recent Admin Actions',
      query: { action: 'USER_APPROVED' },
      sort: { timestamp: -1 },
      expectedIndex: 'timestamp_action'
    },
    {
      name: 'Admin Activity Log',
      query: { adminId: new ObjectId() },
      sort: { timestamp: -1 },
      expectedIndex: 'adminId_timestamp'
    },
    {
      name: 'Bulk Operations Analysis',
      query: { action: 'BULK_USER_APPROVED', bulkCount: { $gte: 5 } },
      sort: { timestamp: -1 },
      expectedIndex: 'action_bulkCount_timestamp'
    }
  ],

  errorlogs: [
    {
      name: 'Unresolved Errors',
      query: { 'resolution.status': 'new' },
      sort: { timestamp: -1 },
      expectedIndex: 'timestamp_resolutionStatus'
    },
    {
      name: 'Critical Errors',
      query: { 'analytics.severity': 'critical' },
      sort: { timestamp: -1 },
      expectedIndex: 'severity_timestamp'
    },
    {
      name: 'Error Type Analysis',
      query: { errorType: 'ValidationError', statusCode: 400 },
      sort: { timestamp: -1 },
      expectedIndex: 'errorType_statusCode_timestamp'
    },
    {
      name: 'User Error Analysis',
      query: { 'userContext.email': 'user@example.com' },
      sort: { timestamp: -1 },
      expectedIndex: 'userEmail_timestamp'
    }
  ]
};

/**
 * List all indexes for a collection
 */
async function listCollectionIndexes(db, collectionName) {
  try {
    const collection = db.collection(collectionName);
    const indexes = await collection.listIndexes().toArray();
    
    console.log(`\n📋 Indexes for ${collectionName} collection:`);
    indexes.forEach(index => {
      const keys = Object.keys(index.key).map(key => {
        const direction = index.key[key] === 1 ? '↑' : index.key[key] === -1 ? '↓' : index.key[key];
        return `${key}:${direction}`;
      }).join(', ');
      
      const options = [];
      if (index.unique) options.push('unique');
      if (index.sparse) options.push('sparse');
      if (index.background) options.push('background');
      
      const optionsStr = options.length > 0 ? ` (${options.join(', ')})` : '';
      console.log(`  📌 ${index.name}: {${keys}}${optionsStr}`);
    });
    
    return indexes;
  } catch (error) {
    console.error(`❌ Error listing indexes for ${collectionName}:`, error.message);
    return [];
  }
}

/**
 * Test query performance and index usage
 */
async function testQueryPerformance(db, collectionName, testQuery) {
  try {
    const collection = db.collection(collectionName);
    
    // Build the query
    let query = collection.find(testQuery.query);
    if (testQuery.sort) {
      query = query.sort(testQuery.sort);
    }
    
    // Get execution stats
    const explain = await query.explain('executionStats');
    const executionStats = explain.executionStats;
    
    // Extract key metrics
    const indexUsed = explain.queryPlanner?.winningPlan?.inputStage?.indexName || 
                     explain.queryPlanner?.winningPlan?.shards?.[0]?.winningPlan?.inputStage?.indexName ||
                     'COLLSCAN';
    
    const docsExamined = executionStats.totalDocsExamined;
    const docsReturned = executionStats.totalDocsReturned;
    const executionTime = executionStats.executionTimeMillis;
    
    // Determine if the expected index was used
    const expectedIndexUsed = indexUsed === testQuery.expectedIndex || indexUsed.includes(testQuery.expectedIndex);
    
    console.log(`\n🔍 Query: ${testQuery.name}`);
    console.log(`  📊 Index Used: ${indexUsed} ${expectedIndexUsed ? '✅' : '⚠️'}`);
    console.log(`  📄 Docs Examined: ${docsExamined}`);
    console.log(`  📋 Docs Returned: ${docsReturned}`);
    console.log(`  ⏱️  Execution Time: ${executionTime}ms`);
    
    if (!expectedIndexUsed && indexUsed === 'COLLSCAN') {
      console.log(`  ⚠️  WARNING: Collection scan detected! Expected index: ${testQuery.expectedIndex}`);
    }
    
    return {
      queryName: testQuery.name,
      indexUsed,
      expectedIndex: testQuery.expectedIndex,
      expectedIndexUsed,
      docsExamined,
      docsReturned,
      executionTime,
      efficiency: docsReturned > 0 ? (docsReturned / docsExamined) : 0
    };
    
  } catch (error) {
    console.error(`❌ Error testing query '${testQuery.name}':`, error.message);
    return null;
  }
}

/**
 * Get index usage statistics
 */
async function getIndexStats(db, collectionName) {
  try {
    const collection = db.collection(collectionName);
    const stats = await collection.aggregate([
      { $indexStats: {} }
    ]).toArray();
    
    console.log(`\n📈 Index Usage Statistics for ${collectionName}:`);
    stats.forEach(stat => {
      const usage = stat.accesses.ops || 0;
      const lastUsed = stat.accesses.since ? new Date(stat.accesses.since).toLocaleString() : 'Never';
      console.log(`  📊 ${stat.name}: ${usage} operations (since ${lastUsed})`);
    });
    
    return stats;
  } catch (error) {
    console.error(`❌ Error getting index stats for ${collectionName}:`, error.message);
    return [];
  }
}

/**
 * Main verification function
 */
async function verifyIndexes() {
  let client;
  
  try {
    console.log('🔍 GamePlan Database Index Verification Starting...');
    console.log(`📍 Connecting to: ${MONGO_URI.replace(/\/\/.*@/, '//***:***@')}`);
    
    // Connect to MongoDB
    client = new MongoClient(MONGO_URI);
    await client.connect();
    
    const db = client.db(DB_NAME);
    
    // Verify database connection
    await db.admin().ping();
    console.log('✅ Database connection established');
    
    // Get database statistics
    const dbStats = await db.stats();
    console.log(`\n📊 Database Statistics:`);
    console.log(`  📦 Collections: ${dbStats.collections}`);
    console.log(`  📄 Documents: ${dbStats.objects.toLocaleString()}`);
    console.log(`  💾 Data Size: ${(dbStats.dataSize / 1024 / 1024).toFixed(2)} MB`);
    console.log(`  🗂️  Index Size: ${(dbStats.indexSize / 1024 / 1024).toFixed(2)} MB`);
    
    // List indexes for each collection
    console.log('\n' + '='.repeat(60));
    console.log('📋 INDEX INVENTORY');
    console.log('='.repeat(60));
    
    const allIndexes = {};
    for (const collectionName of Object.keys(TEST_QUERIES)) {
      allIndexes[collectionName] = await listCollectionIndexes(db, collectionName);
    }
    
    // Test query performance
    console.log('\n' + '='.repeat(60));
    console.log('🚀 QUERY PERFORMANCE TESTING');
    console.log('='.repeat(60));
    
    const performanceResults = [];
    
    for (const [collectionName, queries] of Object.entries(TEST_QUERIES)) {
      console.log(`\n🎯 Testing ${collectionName} queries...`);
      
      for (const testQuery of queries) {
        const result = await testQueryPerformance(db, collectionName, testQuery);
        if (result) {
          performanceResults.push({ collection: collectionName, ...result });
        }
      }
    }
    
    // Get index usage statistics
    console.log('\n' + '='.repeat(60));
    console.log('📈 INDEX USAGE STATISTICS');
    console.log('='.repeat(60));
    
    for (const collectionName of Object.keys(TEST_QUERIES)) {
      await getIndexStats(db, collectionName);
    }
    
    // Performance summary
    console.log('\n' + '='.repeat(60));
    console.log('📊 PERFORMANCE SUMMARY');
    console.log('='.repeat(60));
    
    const totalQueries = performanceResults.length;
    const indexedQueries = performanceResults.filter(r => r.expectedIndexUsed).length;
    const collectionScans = performanceResults.filter(r => r.indexUsed === 'COLLSCAN').length;
    const avgExecutionTime = performanceResults.reduce((sum, r) => sum + r.executionTime, 0) / totalQueries;
    const avgEfficiency = performanceResults.reduce((sum, r) => sum + r.efficiency, 0) / totalQueries;
    
    console.log(`\n📈 Overall Performance Metrics:`);
    console.log(`  🎯 Total Queries Tested: ${totalQueries}`);
    console.log(`  ✅ Queries Using Expected Index: ${indexedQueries} (${((indexedQueries/totalQueries)*100).toFixed(1)}%)`);
    console.log(`  ⚠️  Collection Scans: ${collectionScans} (${((collectionScans/totalQueries)*100).toFixed(1)}%)`);
    console.log(`  ⏱️  Average Execution Time: ${avgExecutionTime.toFixed(2)}ms`);
    console.log(`  🎯 Average Query Efficiency: ${(avgEfficiency*100).toFixed(1)}%`);
    
    // Recommendations
    console.log(`\n💡 Recommendations:`);
    if (collectionScans > 0) {
      console.log(`  ⚠️  ${collectionScans} queries are still using collection scans. Consider reviewing index definitions.`);
    }
    if (avgExecutionTime > 100) {
      console.log(`  ⚠️  Average execution time is high. Consider adding more specific indexes.`);
    }
    if (indexedQueries === totalQueries) {
      console.log(`  🎉 Excellent! All queries are using appropriate indexes.`);
    }
    
    console.log('\n🎉 Index verification complete!');
    
  } catch (error) {
    console.error('💥 Fatal error during index verification:', error.message);
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
  verifyIndexes().catch(console.error);
}

module.exports = { verifyIndexes, TEST_QUERIES };
