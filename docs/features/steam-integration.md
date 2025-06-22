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
