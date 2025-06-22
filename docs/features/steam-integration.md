# Steam Integration

GamePlan includes comprehensive Steam API integration that automatically manages Steam App IDs for games and provides update notifications for events.

## Overview

The Steam integration system provides seamless connection to Steam's public APIs without requiring authentication, enabling rich game data and automatic update notifications.

## Features

### 🎮 Automatic Steam App ID Management
- **Smart Game Search**: Search Steam's entire catalog when adding games
- **Automatic Population**: Steam App IDs are automatically assigned to games
- **Rich Game Data**: Includes descriptions, images, developers, and publishers
- **Platform Detection**: Automatically detects supported platforms

### 🔔 Update Notifications
- **Automatic Monitoring**: Events automatically inherit Steam App IDs from games
- **Update Detection**: Checks Steam news for game updates, patches, and hotfixes
- **Event Integration**: Update notifications appear on event pages

### 👨‍💼 Enhanced Admin Experience
- **Visual Game Search**: Search with game images and descriptions
- **Fuzzy Matching**: Intelligent search that finds games even with partial names
- **Manual Override**: Option to add games without Steam integration
- **Existing Game Management**: View Steam integration status for all games

## How It Works

### For Admins: Adding Games

1. **Navigate to Admin Panel** (`/admin`)
2. **Search Steam Games**: Type a game name in the search box
3. **Select Game**: Click on the correct game from search results
4. **Review Details**: Game name, description, and Steam App ID are auto-filled
5. **Save Game**: The game is saved with full Steam integration

### For Users: Creating Events

1. **Select Game**: Choose from the dropdown (same as before)
2. **Automatic Integration**: Steam App ID is automatically applied
3. **Visual Feedback**: See Steam integration status for selected game
4. **Update Notifications**: Events automatically check for game updates

## Technical Implementation

### Steam Service (`services/steamService.js`)
- **App List Caching**: Caches Steam's app list for 24 hours
- **Fuzzy Search**: Intelligent matching algorithm with scoring
- **Rate Limiting**: Built-in delays to respect Steam API limits
- **Error Handling**: Graceful fallbacks when Steam API is unavailable

### Database Schema Updates

#### Game Model
```javascript
{
  name: String,
  description: String,
  platforms: [String],
  steamAppId: Number,           // Steam App ID
  steamData: {                 // Rich Steam data
    name: String,
    short_description: String,
    header_image: String,
    developers: [String],
    publishers: [String]
  }
}
```

#### Event Model
```javascript
{
  // ... existing fields
  steamAppId: Number  // Automatically inherited from game
}
```

### API Endpoints
- `GET /api/steam/search?q=<query>` - Search Steam games (admin only)
- Enhanced `/admin/add-game` - Supports Steam integration data

## Configuration

### Environment Variables
**No Steam API key required!** The integration uses Steam's public APIs that don't require authentication:

- `ISteamApps/GetAppList/v2/` - Gets list of all Steam games
- `store.steampowered.com/api/appdetails` - Gets game details  
- `ISteamNews/GetNewsForApp/v2/` - Gets game news

This means you can use all Steam features without needing to:
- Register for a Steam API key
- Configure any Steam-related environment variables
- Worry about API rate limits or authentication

### Rate Limiting
- Steam app list: Cached for 24 hours
- Game searches: 1-second delay between requests during migration
- Update checks: Built-in timeout handling

## Migration

### Existing Games
Run the migration script to add Steam App IDs to existing games:

```bash
node utils/migrateSteamAppIds.js
```

This script:
- Finds games without Steam App IDs
- Searches Steam for matches
- Auto-assigns high-confidence matches (score > 80)
- Provides manual review recommendations for low-confidence matches

### Migration Features
- **Smart Matching**: Only assigns Steam App IDs for high-confidence matches
- **Rate Limiting**: Includes delays to avoid Steam API rate limits
- **Progress Reporting**: Shows detailed progress and results
- **Safe Operation**: Never overwrites existing Steam App IDs

## Usage Examples

### Admin: Adding a New Game
1. Go to `/admin`
2. Type "Cyberpunk" in the Steam search
3. Select "Cyberpunk 2077" from results
4. Game is automatically populated with:
   - Name: "Cyberpunk 2077"
   - Steam App ID: 1091500
   - Description: Steam's official description
   - Platform: PC (detected from Steam)

### User: Creating an Event
1. Go to `/event/new`
2. Select "Cyberpunk 2077" from game dropdown
3. See green "Steam Integration Active" message
4. Create event - Steam App ID 1091500 is automatically assigned
5. Event page will show update notifications when available

## API Reference

### Steam Service Methods

```javascript
// Search for games
const results = await steamService.searchGames('game name', limit);

// Get game details
const details = await steamService.getGameDetails(appId);

// Check for updates
const updates = await steamService.checkForUpdates(appId);

// Get game news
const news = await steamService.getGameNews(appId, count);
```

### Response Formats

#### Search Results
```javascript
[{
  appid: 730,
  name: "Counter-Strike 2",
  score: 95,
  short_description: "...",
  header_image: "https://...",
  developers: ["Valve"],
  publishers: ["Valve"]
}]
```

#### Update Check
```javascript
{
  hasUpdate: true,
  news: [/* news items */]
}
```

## Testing

### Test Steam Integration
```bash
node testSteamIntegration.js
```

This tests:
- Steam game search functionality
- Game details retrieval
- Update checking mechanism

### Manual Testing
1. **Admin Panel**: Test game search and addition
2. **Event Creation**: Verify Steam integration status display
3. **Event Pages**: Check update notifications for Steam-integrated games

## Troubleshooting

### Common Issues

#### Steam search returns no results
- Check internet connection
- Verify game name spelling
- Try partial game names (e.g., "Counter" instead of "Counter-Strike")

#### Migration script fails
- Ensure MongoDB connection is working
- Check Steam API availability
- Run with smaller batches if needed

#### Update notifications not showing
- Verify game has Steam App ID assigned
- Check Steam API status
- Updates may take time to appear in Steam news

### Debug Mode
Enable detailed logging by setting debug flags in `steamService.js`:
```javascript
// In steamService.js
console.log('Debug info:', ...);
```

## Benefits

### For Users
- **Seamless Experience**: No need to manually enter Steam App IDs
- **Update Awareness**: Automatic notifications when games are updated
- **Rich Game Information**: Better game descriptions and details

### For Admins
- **Efficient Management**: Quick game addition with Steam search
- **Accurate Data**: Consistent game information from Steam
- **Visual Interface**: Easy game identification with images

### For the Application
- **Data Consistency**: Standardized game information
- **Enhanced Features**: Foundation for future Steam integrations
- **Scalability**: Efficient caching and rate limiting

## Future Enhancements

Potential future features:
- Steam user authentication
- Steam friend integration
- Steam achievement tracking
- Steam workshop mod support
- Steam store price integration

## Related Documentation

- [Game Management](../operations/game-management.md) - Game administration
- [Event Management](../features/event-management.md) - Event creation and management
- [Admin Dashboard](../features/admin-dashboard.md) - Admin interface overview
- [API Documentation](../api/steam-endpoints.md) - Steam API endpoints

This Steam integration significantly enhances GamePlan's functionality while maintaining backward compatibility and providing a smooth user experience.
