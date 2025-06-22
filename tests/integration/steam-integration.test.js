const steamService = require('../../src/services/steamService');

async function testSteamIntegration() {
  console.log('Testing Steam API Integration...\n');
  
  try {
    // Test 1: Search for a popular game
    console.log('Test 1: Searching for "Counter-Strike"');
    const results = await steamService.searchGames('Counter-Strike', 3);
    
    if (results.length > 0) {
      console.log('✓ Steam search working!');
      results.forEach((game, index) => {
        console.log(`  ${index + 1}. ${game.name} (App ID: ${game.appid})`);
        console.log(`     Score: ${game.score}`);
        if (game.short_description) {
          console.log(`     Description: ${game.short_description.substring(0, 100)}...`);
        }
        console.log('');
      });
    } else {
      console.log('✗ No results found');
    }
    
    // Test 2: Get detailed info for a specific game
    console.log('\nTest 2: Getting details for Counter-Strike 2 (App ID: 730)');
    const details = await steamService.getGameDetails(730);
    console.log('✓ Game details retrieved:');
    console.log(`  Description: ${details.short_description?.substring(0, 100)}...`);
    console.log(`  Developers: ${details.developers?.join(', ')}`);
    console.log(`  Publishers: ${details.publishers?.join(', ')}`);
    console.log(`  Platforms: ${details.platforms?.join(', ')}`);
    
    // Test 3: Check for updates
    console.log('\nTest 3: Checking for updates for Counter-Strike 2');
    const updateInfo = await steamService.checkForUpdates(730);
    console.log(`✓ Update check completed:`);
    console.log(`  Has updates: ${updateInfo.hasUpdate}`);
    console.log(`  News items: ${updateInfo.news.length}`);
    
    console.log('\n🎉 All Steam integration tests passed!');
    
  } catch (error) {
    console.error('❌ Steam integration test failed:', error.message);
  }
}

testSteamIntegration();
