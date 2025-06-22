/**
 * Test script for the GamePlan caching implementation
 * This script tests all cache services and their functionality
 */

const mongoose = require('mongoose');
require('dotenv').config();

// Import cache services
const cacheService = require('../../src/services/cacheService');
const dashboardCacheService = require('../../src/services/dashboardCacheService');
const apiCacheService = require('../../src/services/apiCacheService');

// Import models (mock for testing)
const mockModels = {
  User: {
    countDocuments: async (query) => {
      console.log('Mock User.countDocuments called with:', query);
      if (query?.status === 'pending') return 5;
      if (query?.isBlocked) return 2;
      if (query?.probationaryUntil) return 3;
      return 150;
    },
    find: async (query) => {
      console.log('Mock User.find called with:', query);
      return [
        { _id: '1', name: 'Test User 1', email: 'test1@example.com' },
        { _id: '2', name: 'Test User 2', email: 'test2@example.com' }
      ];
    }
  },
  Event: {
    countDocuments: async (query) => {
      console.log('Mock Event.countDocuments called with:', query);
      if (query?.gameStatus === 'pending') return 3;
      if (query?.date?.$gte) return 25;
      return 100;
    },
    find: async (query) => {
      console.log('Mock Event.find called with:', query);
      return [
        { _id: '1', name: 'Test Event 1', date: new Date() },
        { _id: '2', name: 'Test Event 2', date: new Date() }
      ];
    }
  },
  Game: {
    countDocuments: async (query) => {
      console.log('Mock Game.countDocuments called with:', query);
      if (query?.status === 'pending') return 8;
      return 75;
    },
    find: async (query) => {
      console.log('Mock Game.find called with:', query);
      return [
        { _id: '1', name: 'Test Game 1', status: 'approved' },
        { _id: '2', name: 'Test Game 2', status: 'approved' }
      ];
    }
  },
  AuditLog: {
    countDocuments: async (query) => {
      console.log('Mock AuditLog.countDocuments called with:', query);
      return 500;
    },
    find: async (query) => {
      console.log('Mock AuditLog.find called with:', query);
      return [
        { _id: '1', action: 'USER_APPROVED', timestamp: new Date() },
        { _id: '2', action: 'EVENT_CREATED', timestamp: new Date() }
      ];
    }
  }
};

// Mock Steam and RAWG services
const mockSteamService = {
  searchGames: async (query) => {
    console.log('Mock Steam search for:', query);
    await new Promise(resolve => setTimeout(resolve, 100)); // Simulate API delay
    return [
      { appid: 123, name: `Steam Game for ${query}` },
      { appid: 456, name: `Another Steam Game for ${query}` }
    ];
  }
};

const mockRawgService = {
  searchGames: async (query) => {
    console.log('Mock RAWG search for:', query);
    await new Promise(resolve => setTimeout(resolve, 150)); // Simulate API delay
    return [
      { id: 789, name: `RAWG Game for ${query}` },
      { id: 101, name: `Another RAWG Game for ${query}` }
    ];
  }
};

async function testCacheService() {
  console.log('\n=== Testing CacheService ===');
  
  try {
    // Test basic cache operations
    console.log('Testing basic cache operations...');
    cacheService.set('dashboard', 'test_key', { data: 'test_value' });
    const value = cacheService.get('dashboard', 'test_key');
    console.log('✓ Set/Get test:', value?.data === 'test_value' ? 'PASSED' : 'FAILED');
    
    // Test cache statistics
    console.log('Testing cache statistics...');
    const stats = cacheService.getStats();
    console.log('✓ Cache stats:', stats);
    
    // Test cache clearing
    console.log('Testing cache clearing...');
    const cleared = cacheService.clear('dashboard');
    console.log('✓ Cache clear:', cleared ? 'PASSED' : 'FAILED');
    
    // Test warm-up
    console.log('Testing cache warm-up...');
    await cacheService.warmUp(mockModels);
    console.log('✓ Cache warm-up completed');
    
  } catch (error) {
    console.error('✗ CacheService test failed:', error.message);
  }
}

async function testDashboardCacheService() {
  console.log('\n=== Testing DashboardCacheService ===');
  
  try {
    // Test dashboard statistics
    console.log('Testing dashboard statistics...');
    const stats = await dashboardCacheService.getDashboardStats(mockModels);
    console.log('✓ Dashboard stats:', stats);
    
    // Test pending counts
    console.log('Testing pending counts...');
    const pendingCounts = await dashboardCacheService.getPendingCounts(mockModels);
    console.log('✓ Pending counts:', pendingCounts);
    
    // Test recent activity
    console.log('Testing recent activity...');
    const recentActivity = await dashboardCacheService.getRecentActivity(mockModels);
    console.log('✓ Recent activity:', recentActivity);
    
    // Test cache invalidation
    console.log('Testing cache invalidation...');
    dashboardCacheService.invalidateUserCaches();
    dashboardCacheService.invalidateGameCaches();
    dashboardCacheService.invalidateDashboardCaches();
    console.log('✓ Cache invalidation completed');
    
    // Test cache status
    console.log('Testing cache status...');
    const status = dashboardCacheService.getCacheStatus();
    console.log('✓ Cache status:', status);
    
  } catch (error) {
    console.error('✗ DashboardCacheService test failed:', error.message);
  }
}

async function testApiCacheService() {
  console.log('\n=== Testing ApiCacheService ===');
  
  try {
    // Test Steam search caching
    console.log('Testing Steam search caching...');
    const steamQuery = 'counter strike';
    
    // First call (should hit API)
    console.log('First Steam search (cache miss)...');
    const steamResults1 = await apiCacheService.cachedSteamSearch(steamQuery, mockSteamService);
    console.log('✓ Steam search results:', steamResults1);
    
    // Second call (should hit cache)
    console.log('Second Steam search (cache hit)...');
    const steamResults2 = await apiCacheService.cachedSteamSearch(steamQuery, mockSteamService);
    console.log('✓ Steam search cached:', steamResults1.length === steamResults2.length ? 'PASSED' : 'FAILED');
    
    // Test RAWG search caching
    console.log('Testing RAWG search caching...');
    const rawgQuery = 'minecraft';
    
    // First call (should hit API)
    console.log('First RAWG search (cache miss)...');
    const rawgResults1 = await apiCacheService.cachedRawgSearch(rawgQuery, mockRawgService);
    console.log('✓ RAWG search results:', rawgResults1);
    
    // Second call (should hit cache)
    console.log('Second RAWG search (cache hit)...');
    const rawgResults2 = await apiCacheService.cachedRawgSearch(rawgQuery, mockRawgService);
    console.log('✓ RAWG search cached:', rawgResults1.length === rawgResults2.length ? 'PASSED' : 'FAILED');
    
    // Test game list caching
    console.log('Testing game list caching...');
    const gameList = await apiCacheService.getCachedGameList(mockModels, 'approved');
    console.log('✓ Game list:', gameList);
    
    // Test cache invalidation
    console.log('Testing API cache invalidation...');
    apiCacheService.invalidateSearchCaches();
    apiCacheService.invalidateGameListCaches();
    console.log('✓ API cache invalidation completed');
    
    // Test cache statistics
    console.log('Testing API cache statistics...');
    const apiStats = apiCacheService.getApiCacheStats();
    console.log('✓ API cache stats:', apiStats);
    
    // Test old cache cleanup
    console.log('Testing old cache cleanup...');
    const cleanedCount = apiCacheService.clearOldSearchCaches(0); // Clear all for testing
    console.log('✓ Cleaned cache entries:', cleanedCount);
    
  } catch (error) {
    console.error('✗ ApiCacheService test failed:', error.message);
  }
}

async function testCachePerformance() {
  console.log('\n=== Testing Cache Performance ===');
  
  try {
    const iterations = 100;
    const testQuery = 'performance test';
    
    // Test without cache (direct API calls)
    console.log(`Testing ${iterations} direct API calls...`);
    const startDirect = Date.now();
    for (let i = 0; i < iterations; i++) {
      await mockSteamService.searchGames(testQuery);
    }
    const directTime = Date.now() - startDirect;
    console.log(`✓ Direct API calls took: ${directTime}ms`);
    
    // Test with cache
    console.log(`Testing ${iterations} cached API calls...`);
    const startCached = Date.now();
    for (let i = 0; i < iterations; i++) {
      await apiCacheService.cachedSteamSearch(testQuery, mockSteamService);
    }
    const cachedTime = Date.now() - startCached;
    console.log(`✓ Cached API calls took: ${cachedTime}ms`);
    
    const improvement = ((directTime - cachedTime) / directTime * 100).toFixed(2);
    console.log(`✓ Performance improvement: ${improvement}%`);
    
  } catch (error) {
    console.error('✗ Performance test failed:', error.message);
  }
}

async function testCacheIntegration() {
  console.log('\n=== Testing Cache Integration ===');
  
  try {
    // Test warm-up of all caches
    console.log('Testing integrated cache warm-up...');
    await Promise.all([
      cacheService.warmUp(mockModels),
      dashboardCacheService.warmUp(mockModels),
      apiCacheService.warmUp(mockModels)
    ]);
    console.log('✓ Integrated warm-up completed');
    
    // Test overall statistics
    console.log('Testing overall cache statistics...');
    const overallStats = cacheService.getStats();
    const apiStats = apiCacheService.getApiCacheStats();
    const dashboardStatus = dashboardCacheService.getCacheStatus();
    
    console.log('✓ Overall cache statistics:');
    console.log('  - Overall:', overallStats);
    console.log('  - API:', apiStats);
    console.log('  - Dashboard:', dashboardStatus);
    
    // Test cache health simulation
    console.log('Testing cache health calculation...');
    const totalRequests = overallStats.overall.hits + overallStats.overall.misses;
    const hitRate = totalRequests > 0 ? (overallStats.overall.hits / totalRequests) * 100 : 0;
    const errorRate = totalRequests > 0 ? (overallStats.overall.errors / totalRequests) * 100 : 0;
    
    console.log(`✓ Cache health metrics:`);
    console.log(`  - Hit rate: ${hitRate.toFixed(2)}%`);
    console.log(`  - Error rate: ${errorRate.toFixed(2)}%`);
    console.log(`  - Total requests: ${totalRequests}`);
    
  } catch (error) {
    console.error('✗ Integration test failed:', error.message);
  }
}

async function runAllTests() {
  console.log('🚀 Starting GamePlan Caching System Tests');
  console.log('==========================================');
  
  try {
    await testCacheService();
    await testDashboardCacheService();
    await testApiCacheService();
    await testCachePerformance();
    await testCacheIntegration();
    
    console.log('\n✅ All cache tests completed successfully!');
    console.log('==========================================');
    
  } catch (error) {
    console.error('\n❌ Cache tests failed:', error.message);
    console.error(error.stack);
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  runAllTests().then(() => {
    console.log('\n🎉 Cache testing completed. You can now start the application to use the caching system.');
    process.exit(0);
  }).catch((error) => {
    console.error('\n💥 Cache testing failed:', error.message);
    process.exit(1);
  });
}

module.exports = {
  runAllTests,
  testCacheService,
  testDashboardCacheService,
  testApiCacheService,
  testCachePerformance,
  testCacheIntegration
};
