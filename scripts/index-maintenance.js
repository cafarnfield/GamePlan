#!/usr/bin/env node

/**
 * GamePlan Database Index Maintenance Script
 * 
 * This script provides utilities for maintaining and analyzing database indexes,
 * including usage statistics, performance monitoring, and safe index removal.
 * 
 * Usage:
 *   node scripts/index-maintenance.js [command]
 * 
 * Commands:
 *   analyze    - Analyze index usage and performance
 *   cleanup    - Remove unused indexes (interactive)
 *   stats      - Show detailed index statistics
 *   health     - Check index health and recommendations
 */

const { MongoClient } = require('mongodb');
require('dotenv').config();

// Database connection configuration
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/gameplan';
const DB_NAME = 'gameplan';

/**
 * Analyze index usage across all collections
 */
async function analyzeIndexUsage(db) {
  console.log('🔍 Analyzing index usage...\n');
  
  const collections = await db.listCollections().toArray();
  const analysisResults = [];
  
  for (const collInfo of collections) {
    const collectionName = collInfo.name;
    console.log(`📊 Analyzing ${collectionName} collection...`);
    
    try {
      const collection = db.collection(collectionName);
      
      // Get index statistics
      const indexStats = await collection.aggregate([{ $indexStats: {} }]).toArray();
      
      // Get collection statistics
      const collStats = await db.command({ collStats: collectionName });
      
      console.log(`  📄 Documents: ${collStats.count.toLocaleString()}`);
      console.log(`  💾 Size: ${(collStats.size / 1024 / 1024).toFixed(2)} MB`);
      console.log(`  🗂️  Indexes: ${indexStats.length}`);
      
      // Analyze each index
      const indexAnalysis = [];
      for (const stat of indexStats) {
        const usage = stat.accesses.ops || 0;
        const lastUsed = stat.accesses.since ? new Date(stat.accesses.since) : null;
        const daysSinceLastUse = lastUsed ? Math.floor((Date.now() - lastUsed.getTime()) / (1000 * 60 * 60 * 24)) : null;
        
        const analysis = {
          name: stat.name,
          usage: usage,
          lastUsed: lastUsed,
          daysSinceLastUse: daysSinceLastUse,
          isUnused: usage === 0,
          isRarelyUsed: usage > 0 && usage < 10,
          recommendation: getIndexRecommendation(stat.name, usage, daysSinceLastUse)
        };
        
        indexAnalysis.push(analysis);
        
        const statusIcon = usage === 0 ? '❌' : usage < 10 ? '⚠️' : '✅';
        const lastUsedStr = lastUsed ? `${daysSinceLastUse} days ago` : 'Never';
        console.log(`    ${statusIcon} ${stat.name}: ${usage} ops (last used: ${lastUsedStr})`);
      }
      
      analysisResults.push({
        collection: collectionName,
        documentCount: collStats.count,
        size: collStats.size,
        indexes: indexAnalysis
      });
      
    } catch (error) {
      console.error(`  ❌ Error analyzing ${collectionName}:`, error.message);
    }
    
    console.log('');
  }
  
  return analysisResults;
}

/**
 * Get recommendation for an index based on usage patterns
 */
function getIndexRecommendation(indexName, usage, daysSinceLastUse) {
  // Never remove critical system indexes
  if (indexName === '_id_' || indexName.includes('unique') || indexName.includes('email')) {
    return 'KEEP - Critical system index';
  }
  
  if (usage === 0) {
    if (daysSinceLastUse === null || daysSinceLastUse > 30) {
      return 'CONSIDER_REMOVAL - Unused for 30+ days';
    } else {
      return 'MONITOR - Recently created, monitor usage';
    }
  }
  
  if (usage < 5 && daysSinceLastUse > 7) {
    return 'REVIEW - Low usage, may be redundant';
  }
  
  if (usage >= 100) {
    return 'KEEP - High usage, critical for performance';
  }
  
  return 'KEEP - Normal usage';
}

/**
 * Generate index health report
 */
async function generateHealthReport(db, analysisResults) {
  console.log('🏥 Generating Index Health Report...\n');
  
  let totalIndexes = 0;
  let unusedIndexes = 0;
  let rarelyUsedIndexes = 0;
  let criticalIndexes = 0;
  let totalSize = 0;
  
  const recommendations = {
    remove: [],
    review: [],
    monitor: []
  };
  
  for (const result of analysisResults) {
    totalSize += result.size;
    
    for (const index of result.indexes) {
      totalIndexes++;
      
      if (index.isUnused) {
        unusedIndexes++;
      } else if (index.isRarelyUsed) {
        rarelyUsedIndexes++;
      } else if (index.usage >= 100) {
        criticalIndexes++;
      }
      
      // Categorize recommendations
      if (index.recommendation.startsWith('CONSIDER_REMOVAL')) {
        recommendations.remove.push({
          collection: result.collection,
          index: index.name,
          reason: index.recommendation
        });
      } else if (index.recommendation.startsWith('REVIEW')) {
        recommendations.review.push({
          collection: result.collection,
          index: index.name,
          reason: index.recommendation
        });
      } else if (index.recommendation.startsWith('MONITOR')) {
        recommendations.monitor.push({
          collection: result.collection,
          index: index.name,
          reason: index.recommendation
        });
      }
    }
  }
  
  // Display health summary
  console.log('📊 Index Health Summary:');
  console.log(`  🎯 Total Indexes: ${totalIndexes}`);
  console.log(`  ✅ Critical Indexes (100+ ops): ${criticalIndexes}`);
  console.log(`  ⚠️  Rarely Used Indexes (<10 ops): ${rarelyUsedIndexes}`);
  console.log(`  ❌ Unused Indexes: ${unusedIndexes}`);
  console.log(`  💾 Total Database Size: ${(totalSize / 1024 / 1024).toFixed(2)} MB`);
  
  const healthScore = Math.round(((criticalIndexes + (totalIndexes - unusedIndexes - rarelyUsedIndexes)) / totalIndexes) * 100);
  console.log(`  🏥 Index Health Score: ${healthScore}%`);
  
  // Display recommendations
  if (recommendations.remove.length > 0) {
    console.log('\n🗑️  Indexes Recommended for Removal:');
    recommendations.remove.forEach(rec => {
      console.log(`  ❌ ${rec.collection}.${rec.index} - ${rec.reason}`);
    });
  }
  
  if (recommendations.review.length > 0) {
    console.log('\n🔍 Indexes to Review:');
    recommendations.review.forEach(rec => {
      console.log(`  ⚠️  ${rec.collection}.${rec.index} - ${rec.reason}`);
    });
  }
  
  if (recommendations.monitor.length > 0) {
    console.log('\n👀 Indexes to Monitor:');
    recommendations.monitor.forEach(rec => {
      console.log(`  👁️  ${rec.collection}.${rec.index} - ${rec.reason}`);
    });
  }
  
  return {
    summary: {
      totalIndexes,
      criticalIndexes,
      rarelyUsedIndexes,
      unusedIndexes,
      healthScore
    },
    recommendations
  };
}

/**
 * Interactive cleanup of unused indexes
 */
async function interactiveCleanup(db, recommendations) {
  if (recommendations.remove.length === 0) {
    console.log('🎉 No indexes recommended for removal!');
    return;
  }
  
  console.log('\n🗑️  Interactive Index Cleanup');
  console.log('⚠️  WARNING: This will permanently remove indexes!');
  console.log('💡 You can always recreate them using create-indexes.js\n');
  
  const readline = require('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  
  const question = (prompt) => new Promise(resolve => rl.question(prompt, resolve));
  
  for (const rec of recommendations.remove) {
    const answer = await question(`Remove ${rec.collection}.${rec.index}? (y/N): `);
    
    if (answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes') {
      try {
        const collection = db.collection(rec.collection);
        await collection.dropIndex(rec.index);
        console.log(`  ✅ Removed ${rec.collection}.${rec.index}`);
      } catch (error) {
        console.error(`  ❌ Failed to remove ${rec.collection}.${rec.index}:`, error.message);
      }
    } else {
      console.log(`  ⏭️  Skipped ${rec.collection}.${rec.index}`);
    }
  }
  
  rl.close();
}

/**
 * Show detailed index statistics
 */
async function showDetailedStats(db) {
  console.log('📈 Detailed Index Statistics\n');
  
  const collections = await db.listCollections().toArray();
  
  for (const collInfo of collections) {
    const collectionName = collInfo.name;
    console.log(`📊 ${collectionName.toUpperCase()} COLLECTION`);
    console.log('='.repeat(50));
    
    try {
      const collection = db.collection(collectionName);
      
      // Get all indexes
      const indexes = await collection.listIndexes().toArray();
      const indexStats = await collection.aggregate([{ $indexStats: {} }]).toArray();
      
      // Merge index info with stats
      const indexDetails = indexes.map(index => {
        const stats = indexStats.find(stat => stat.name === index.name);
        return {
          ...index,
          usage: stats ? stats.accesses.ops : 0,
          lastUsed: stats ? stats.accesses.since : null
        };
      });
      
      // Sort by usage (descending)
      indexDetails.sort((a, b) => (b.usage || 0) - (a.usage || 0));
      
      indexDetails.forEach(index => {
        const keys = Object.keys(index.key).map(key => {
          const direction = index.key[key] === 1 ? '↑' : index.key[key] === -1 ? '↓' : index.key[key];
          return `${key}:${direction}`;
        }).join(', ');
        
        const options = [];
        if (index.unique) options.push('unique');
        if (index.sparse) options.push('sparse');
        if (index.background) options.push('background');
        
        const optionsStr = options.length > 0 ? ` (${options.join(', ')})` : '';
        const lastUsedStr = index.lastUsed ? new Date(index.lastUsed).toLocaleDateString() : 'Never';
        
        console.log(`\n📌 ${index.name}`);
        console.log(`   Keys: {${keys}}${optionsStr}`);
        console.log(`   Usage: ${index.usage || 0} operations`);
        console.log(`   Last Used: ${lastUsedStr}`);
        
        if (index.textIndexVersion) {
          console.log(`   Type: Text Search Index`);
        }
      });
      
    } catch (error) {
      console.error(`❌ Error getting stats for ${collectionName}:`, error.message);
    }
    
    console.log('\n');
  }
}

/**
 * Main execution function
 */
async function main() {
  const command = process.argv[2] || 'analyze';
  let client;
  
  try {
    console.log('🔧 GamePlan Index Maintenance Tool');
    console.log(`📍 Connecting to: ${MONGO_URI.replace(/\/\/.*@/, '//***:***@')}`);
    
    // Connect to MongoDB
    client = new MongoClient(MONGO_URI);
    await client.connect();
    
    const db = client.db(DB_NAME);
    
    // Verify database connection
    await db.admin().ping();
    console.log('✅ Database connection established\n');
    
    switch (command) {
      case 'analyze':
        const analysisResults = await analyzeIndexUsage(db);
        await generateHealthReport(db, analysisResults);
        break;
        
      case 'cleanup':
        const cleanupAnalysis = await analyzeIndexUsage(db);
        const healthReport = await generateHealthReport(db, cleanupAnalysis);
        await interactiveCleanup(db, healthReport.recommendations);
        break;
        
      case 'stats':
        await showDetailedStats(db);
        break;
        
      case 'health':
        const healthAnalysis = await analyzeIndexUsage(db);
        await generateHealthReport(db, healthAnalysis);
        break;
        
      default:
        console.log('❌ Unknown command. Available commands: analyze, cleanup, stats, health');
        process.exit(1);
    }
    
    console.log('\n🎉 Index maintenance complete!');
    
  } catch (error) {
    console.error('💥 Fatal error during index maintenance:', error.message);
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
  main().catch(console.error);
}

module.exports = {
  analyzeIndexUsage,
  generateHealthReport,
  showDetailedStats
};
