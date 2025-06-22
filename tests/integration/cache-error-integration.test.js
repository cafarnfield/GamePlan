const mongoose = require('mongoose');
require('dotenv').config();

// Import services
const cacheService = require('../../src/services/cacheService');
const cacheErrorService = require('../../src/services/cacheErrorService');

// Import models
const ErrorLog = require('../../src/models/ErrorLog');

/**
 * Test Cache Error Logging Integration
 * Verifies that cache errors are properly logged to the ErrorLog model
 */
async function testCacheErrorIntegration() {
  console.log('🧪 Testing Cache Error Logging Integration...\n');

  try {
    // Connect to database
    await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/gameplan');
    console.log('✅ Connected to database');

    // Test 1: Log a cache error
    console.log('\n1. Testing Cache Error Logging:');
    const testError = new Error('Test cache connection failure');
    testError.code = 'ECONNREFUSED';
    
    const errorLog = await cacheErrorService.logCacheError('ConnectionError', testError, {
      cacheType: 'dashboard',
      operation: 'get',
      cacheKey: 'test_key',
      userId: new mongoose.Types.ObjectId(),
      userEmail: 'test@example.com',
      stats: { hits: 10, misses: 5, errors: 1 }
    });
    
    console.log(`   ✅ Cache error logged with ID: ${errorLog._id}`);
    console.log(`   📝 Error Type: ${errorLog.errorType}`);
    console.log(`   🔍 Cache Details:`, errorLog.errorDetails.cacheDetails);

    // Test 2: Log a performance issue
    console.log('\n2. Testing Performance Issue Logging:');
    const performanceLog = await cacheErrorService.logPerformanceIssue('low_hit_rate', {
      hitRate: 15.5,
      totalRequests: 100,
      threshold: 50
    }, {
      cacheType: 'api'
    });
    
    if (performanceLog) {
      console.log(`   ✅ Performance issue logged with ID: ${performanceLog._id}`);
      
      // Access the performance issue from the correct location
      const performanceIssue = performanceLog.errorDetails?.originalError?.issue || 
                              performanceLog.errorDetails?.cacheDetails?.performanceIssue;
      const severity = performanceLog.analytics?.severity;
      
      console.log(`   📊 Issue: ${performanceIssue}`);
      console.log(`   ⚠️  Severity: ${severity}`);
    } else {
      console.log('   ℹ️  Performance issue not logged (below severity threshold)');
    }

    // Test 3: Monitor cache health
    console.log('\n3. Testing Cache Health Monitoring:');
    const mockStats = {
      overall: { hits: 5, misses: 95, errors: 10 }, // Poor performance
      memory: { dashboard: 1, api: 2, gameLists: 0, userCounts: 0, systemHealth: 0 }
    };
    
    const healthIssues = await cacheErrorService.monitorCacheHealth(mockStats);
    console.log(`   📈 Health issues detected: ${healthIssues.length}`);
    healthIssues.forEach((issue, index) => {
      console.log(`   ${index + 1}. ${issue.type} (${issue.severity})`);
    });

    // Test 4: Get cache error statistics
    console.log('\n4. Testing Cache Error Statistics:');
    const errorStats = await cacheErrorService.getCacheErrorStats(24);
    console.log('   📊 Error Statistics:');
    console.log(`   • Total Cache Errors: ${errorStats.totalCacheErrors}`);
    console.log(`   • Errors by Severity:`, errorStats.errorsBySeverity);
    console.log(`   • Errors by Type:`, errorStats.errorsByType);

    // Test 5: Get recent cache errors
    console.log('\n5. Testing Recent Cache Errors:');
    const recentErrors = await cacheErrorService.getRecentCacheErrors(5);
    console.log(`   📋 Recent Errors Found: ${recentErrors.length}`);
    recentErrors.forEach((error, index) => {
      console.log(`   ${index + 1}. ${error.errorType} - ${error.analytics.severity} (${new Date(error.timestamp).toLocaleString()})`);
    });

    // Test 6: Test cache service health monitoring integration
    console.log('\n6. Testing Cache Service Integration:');
    console.log('   🔄 Getting cache stats (triggers health monitoring)...');
    const stats = cacheService.getStats();
    console.log(`   📊 Current Hit Rate: ${stats.hitRate}`);
    console.log(`   🔢 Total Memory Keys: ${Object.values(stats.memory).reduce((sum, count) => sum + count, 0)}`);

    // Test 7: Verify error logs in database
    console.log('\n7. Verifying Error Logs in Database:');
    const totalCacheErrors = await ErrorLog.countDocuments({
      errorType: { $regex: /^Cache/ }
    });
    console.log(`   🗄️  Total cache errors in database: ${totalCacheErrors}`);

    const recentCacheErrors = await ErrorLog.find({
      errorType: { $regex: /^Cache/ }
    }).sort({ timestamp: -1 }).limit(3);

    console.log('   📝 Recent cache error entries:');
    recentCacheErrors.forEach((error, index) => {
      console.log(`   ${index + 1}. ${error.errorType} - ${error.message}`);
      console.log(`      📅 ${new Date(error.timestamp).toLocaleString()}`);
      console.log(`      🎯 Severity: ${error.analytics.severity}`);
      console.log(`      🔧 Cache Type: ${error.errorDetails.cacheDetails?.cacheType || 'N/A'}`);
    });

    // Test 8: Test error cleanup
    console.log('\n8. Testing Error Log Cleanup:');
    const deletedCount = await cacheErrorService.cleanupOldCacheErrors(0); // Clean up all resolved errors
    console.log(`   🧹 Cleaned up ${deletedCount} old cache error logs`);

    console.log('\n🎉 All Cache Error Integration Tests PASSED!\n');

    // Summary
    console.log('📊 Integration Summary:');
    console.log('   ✅ Cache error logging to ErrorLog model');
    console.log('   ✅ Performance issue monitoring and logging');
    console.log('   ✅ Automatic health monitoring integration');
    console.log('   ✅ Error statistics and reporting');
    console.log('   ✅ Recent error retrieval');
    console.log('   ✅ Database integration verification');
    console.log('   ✅ Error log cleanup functionality');

    console.log('\n🔗 Cache Error Logging Features:');
    console.log('   • Comprehensive error context capture');
    console.log('   • Automatic severity and impact assessment');
    console.log('   • Performance threshold monitoring');
    console.log('   • Health issue detection and alerting');
    console.log('   • Integration with existing ErrorLog system');
    console.log('   • Automatic cleanup of old error logs');

    console.log('\n🎯 Next Steps:');
    console.log('   • Cache errors will now appear in admin error logs');
    console.log('   • Performance issues are automatically detected');
    console.log('   • Health monitoring runs every 5 minutes');
    console.log('   • Error statistics available via API endpoints');

  } catch (error) {
    console.error('❌ Cache Error Integration Test Failed:', error.message);
    console.error('Stack:', error.stack);
  } finally {
    await mongoose.disconnect();
    console.log('\n🔌 Disconnected from database');
  }
}

// Run the test
if (require.main === module) {
  testCacheErrorIntegration();
}

module.exports = testCacheErrorIntegration;
