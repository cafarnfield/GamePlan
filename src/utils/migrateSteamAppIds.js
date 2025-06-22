const mongoose = require('mongoose');
require('dotenv').config();

const Game = require('../models/Game');
const steamService = require('../services/steamService');

async function migrateSteamAppIds() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('Connected to MongoDB');
    
    const games = await Game.find({ steamAppId: { $exists: false } });
    console.log(`Found ${games.length} games without Steam App IDs`);
    
    for (const game of games) {
      console.log(`\nProcessing: ${game.name}`);
      
      try {
        const steamResults = await steamService.searchGames(game.name, 5);
        
        if (steamResults.length > 0) {
          // Find the best match (highest score)
          const bestMatch = steamResults[0];
          
          console.log(`Best match found: ${bestMatch.name} (App ID: ${bestMatch.appid}, Score: ${bestMatch.score})`);
          
          // Only auto-assign if it's a very good match (score > 80)
          if (bestMatch.score > 80) {
            game.steamAppId = bestMatch.appid;
            game.steamData = {
              name: bestMatch.name,
              short_description: bestMatch.short_description,
              header_image: bestMatch.header_image,
              developers: bestMatch.developers,
              publishers: bestMatch.publishers
            };
            
            // Update platforms if Steam data has platform info
            if (bestMatch.platforms && bestMatch.platforms.length > 0) {
              game.platforms = [...new Set([...game.platforms, ...bestMatch.platforms])];
            }
            
            await game.save();
            console.log(`✓ Updated ${game.name} with Steam App ID: ${bestMatch.appid}`);
          } else {
            console.log(`⚠ Match score too low (${bestMatch.score}), skipping auto-assignment`);
            console.log(`  Manual review recommended for: ${game.name}`);
          }
        } else {
          console.log(`✗ No Steam matches found for: ${game.name}`);
        }
        
        // Add delay to avoid rate limiting
        await new Promise(resolve => setTimeout(resolve, 1000));
        
      } catch (error) {
        console.error(`Error processing ${game.name}:`, error.message);
      }
    }
    
    console.log('\nMigration completed!');
    
    // Show summary
    const updatedGames = await Game.find({ steamAppId: { $exists: true } });
    console.log(`\nSummary:`);
    console.log(`- Total games: ${await Game.countDocuments()}`);
    console.log(`- Games with Steam integration: ${updatedGames.length}`);
    console.log(`- Games without Steam integration: ${await Game.countDocuments() - updatedGames.length}`);
    
    process.exit(0);
  } catch (error) {
    console.error('Migration error:', error);
    process.exit(1);
  }
}

// Run migration if called directly
if (require.main === module) {
  migrateSteamAppIds();
}

module.exports = migrateSteamAppIds;
