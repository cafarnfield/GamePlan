# Development Mode Auto-Login

This document explains how to use the auto-login feature for development and how to re-enable normal authentication for production.

## Current Status

The app is currently configured for **DEVELOPMENT MODE** with auto-login enabled.

## How It Works

When `AUTO_LOGIN_ADMIN=true` and `NODE_ENV=development` are set in the `.env` file:

- The app automatically logs you in as an admin user
- No login credentials are required
- Full admin access is granted immediately
- A development banner appears at the top of the page
- All protected routes work without authentication

### Mock Admin User Details:
- **Name:** Development Admin
- **Email:** dev-admin@gameplan.local
- **Game Nickname:** DevAdmin
- **Admin Status:** Yes
- **Blocked Status:** No

## Switching Between Modes

### To DISABLE Auto-Login (Production Mode)

Edit the `.env` file and change:
```
AUTO_LOGIN_ADMIN=false
```

Or remove the line entirely. Then restart the server.

### To ENABLE Auto-Login (Development Mode)

Edit the `.env` file and set:
```
AUTO_LOGIN_ADMIN=true
NODE_ENV=development
```

Then restart the server.

## Visual Indicators

- **Development Mode:** Orange banner at top: "🔧 DEVELOPMENT MODE - Auto-logged in as Admin"
- **Production Mode:** No banner, normal login required

## Security Notes

⚠️ **IMPORTANT:** 
- Auto-login only works when `NODE_ENV=development`
- This prevents accidental auto-login in production environments
- Always verify your environment variables before deploying

## Testing the Switch

1. **Test Development Mode:**
   - Set `AUTO_LOGIN_ADMIN=true`
   - Restart server
   - Visit homepage - should see development banner
   - Should have immediate admin access

2. **Test Production Mode:**
   - Set `AUTO_LOGIN_ADMIN=false`
   - Restart server
   - Visit homepage - should redirect to login
   - Normal authentication required

## Files Modified

- `.env` - Added `AUTO_LOGIN_ADMIN` variable
- `app.js` - Added auto-login middleware and mock admin user
- `views/index.ejs` - Added development banner
- `public/styles.css` - Added banner styling

## Reverting Changes

To completely remove auto-login functionality:

1. Remove `AUTO_LOGIN_ADMIN` from `.env`
2. Remove auto-login middleware from `app.js`
3. Remove development banner from `views/index.ejs`
4. Remove banner CSS from `public/styles.css`
