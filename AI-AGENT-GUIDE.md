# 🤖 GamePlan AI Agent Guide

**Purpose**: This document provides AI agents with essential knowledge to understand and work effectively with the GamePlan application.

**Usage**: Read this document first before performing any development, debugging, or analysis tasks on GamePlan.

---

## 🎯 Quick Start for AI Agents

### What is GamePlan?
GamePlan is a **gaming event management web application** built with Node.js/Express and MongoDB. Users can register, create gaming events, join events, and manage gaming communities with Steam integration.

### Core Workflow
```
User Registration → Admin Approval → Event Creation → Player Participation → Steam Integration
```

### Key Technologies
- **Backend**: Node.js, Express.js, MongoDB (Mongoose)
- **Frontend**: EJS templates, vanilla JavaScript
- **Authentication**: Passport.js with local strategy
- **External APIs**: Steam API, RAWG API
- **Deployment**: Docker, Docker Compose
- **Caching**: node-cache (multi-tier system)

---

## 🏗️ System Architecture Overview

### Application Structure
```
GamePlan/
├── app.js                 # Main application entry point
├── config/               # Application configuration
├── src/
│   ├── models/          # MongoDB schemas (User, Event, Game, etc.)
│   ├── routes/          # Express route handlers
│   ├── services/        # Business logic and external API integrations
│   ├── middleware/      # Authentication, validation, error handling
│   ├── utils/           # Utility functions and helpers
│   ├── validators/      # Input validation schemas (Joi)
│   └── views/           # EJS templates
├── docs/                # Comprehensive documentation
├── scripts/             # Deployment and maintenance scripts
└── tests/               # Test suite (110+ tests)
```

### Core Services Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Routes    │    │   API Routes    │    │  Admin Routes   │
│  (auth, events) │    │ (steam, health) │    │ (user mgmt)     │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────▼─────────────┐
                    │      Middleware Layer     │
                    │ (auth, validation, cache) │
                    └─────────────┬─────────────┘
                                 │
                    ┌─────────────▼─────────────┐
                    │     Service Layer        │
                    │ (steam, email, cache)    │
                    └─────────────┬─────────────┘
                                 │
                    ┌─────────────▼─────────────┐
                    │     Database Layer       │
                    │    (MongoDB/Mongoose)    │
                    └─────────────────────────────┘
```

---

## 📊 Data Models & Relationships

### Core Data Flow
```
User ──creates──> Event ──references──> Game ──integrates──> Steam API
 │                  │                     │
 │                  └──joins──> Players   └──fetches──> Game Data
 │
 └──has──> Roles (admin, superAdmin, user)
```

### User Model (src/models/User.js)
```javascript
{
  // Basic Info
  name: String,
  email: String,
  password: String (bcrypt hashed),
  gameNickname: String,
  
  // Roles & Status
  isAdmin: Boolean,
  isSuperAdmin: Boolean,
  isBlocked: Boolean,
  status: 'pending' | 'approved' | 'rejected',
  
  // Approval Workflow
  approvedBy: ObjectId (ref: User),
  approvalNotes: String,
  registrationIP: String,
  
  // Password Reset
  resetToken: String,
  resetTokenExpiry: Date,
  mustChangePassword: Boolean
}
```

### Event Model (src/models/Event.js)
```javascript
{
  // Event Details
  name: String,
  description: String,
  date: Date,
  playerLimit: Number,
  
  // Relationships
  game: ObjectId (ref: Game),
  createdBy: ObjectId (ref: User),
  players: [ObjectId] (ref: User),
  
  // Game Integration
  steamAppId: Number,
  platforms: ['PC', 'PlayStation', 'Xbox', 'Nintendo Switch'],
  
  // Visibility & Status
  isVisible: Boolean,
  gameStatus: 'approved' | 'pending'
}
```

### Game Model (src/models/Game.js)
```javascript
{
  // Basic Info
  name: String,
  description: String,
  platforms: [String],
  
  // External Integration
  steamAppId: Number,
  steamData: { name, description, image, developers },
  rawgId: Number,
  rawgData: { /* RAWG API data */ },
  
  // Management
  source: 'steam' | 'rawg' | 'manual' | 'admin',
  status: 'pending' | 'approved' | 'rejected',
  addedBy: ObjectId (ref: User),
  
  // Organization
  categories: [String], // Action, RPG, etc.
  tags: [String],
  aliases: [String]
}
```

---

## 🗂️ Codebase Structure Map

### Routes (src/routes/)
- **auth.js** - Login, register, logout, password reset
- **admin.js** - User management, system administration
- **events.js** - Event CRUD operations, joining/leaving
- **games.js** - Game management and search
- **api.js** - Steam/RAWG search, version info
- **health.js** - System health monitoring
- **cache.js** - Cache management (26 endpoints)
- **ipManagement.js** - IP blocking and security

### Services (src/services/)
- **steamService.js** - Steam API integration, game search
- **rawgService.js** - RAWG API integration
- **emailService.js** - Email sending (password reset, notifications)
- **cacheService.js** - Multi-tier caching system
- **dashboardCacheService.js** - Dashboard statistics caching
- **apiCacheService.js** - External API response caching
- **healthService.js** - System health monitoring
- **duplicateDetectionService.js** - Game duplicate detection

### Middleware (src/middleware/)
- **auth.js** - Authentication, authorization, role checking
- **validation.js** - Input validation using Joi schemas
- **errorHandler.js** - Centralized error handling
- **rateLimiting.js** - API rate limiting
- **security.js** - Security headers and protection

### Key Configuration Files
- **config/app.js** - Main application configuration
- **config/database.js** - MongoDB connection setup
- **config/security.js** - Security middleware configuration
- **config/swagger.js** - API documentation setup

---

## 🔄 User Journeys & Workflows

### 1. User Registration & Approval
```
1. User registers → status: 'pending'
2. Admin reviews → approves/rejects
3. User gets email notification
4. Approved users can create events
```

### 2. Event Creation Workflow
```
1. User selects game from dropdown
2. Fills event details (date, description, player limit)
3. System auto-assigns steamAppId from game
4. Event becomes visible to other users
5. Users can join/leave event
```

### 3. Game Management Workflow
```
1. Admin searches Steam/RAWG APIs
2. Selects game from search results
3. Game data auto-populated
4. Game added to system
5. Available in event creation dropdown
```

### 4. Steam Integration Flow
```
1. Game has steamAppId
2. Event inherits steamAppId from game
3. System checks Steam news for updates
4. Update notifications shown on event pages
```

---

## 🛠️ Development Patterns

### Adding New Routes
```javascript
// 1. Create route file in src/routes/
const express = require('express');
const router = express.Router();
const { ensureAuthenticated, ensureAdmin } = require('../middleware/auth');

// 2. Add validation middleware
const { validateBody } = require('../validators');
const { yourSchema } = require('../validators/yourSchemas');

// 3. Add route with proper middleware chain
router.post('/endpoint', 
  ensureAuthenticated,           // Auth check
  validateBody(yourSchema),      // Input validation
  asyncErrorHandler(async (req, res) => {
    // Your logic here
    res.json({ success: true });
  })
);

// 4. Export and register in app.js
module.exports = router;
```

### Error Handling Pattern
```javascript
// Use asyncErrorHandler for async routes
const { asyncErrorHandler } = require('../middleware/errorHandler');

router.get('/example', asyncErrorHandler(async (req, res) => {
  // Async operations here
  // Errors automatically caught and handled
}));

// Throw specific error types
const { ValidationError, NotFoundError } = require('../utils/errors');
throw new NotFoundError('User', userId);
```

### Validation Pattern
```javascript
// 1. Define schema in src/validators/
const Joi = require('joi');
const { commonSchemas } = require('./schemas/common');

const yourSchema = Joi.object({
  email: commonSchemas.email.required(),
  name: Joi.string().min(2).max(50).required()
});

// 2. Use in routes
const { validateBody } = require('../validators');
router.post('/endpoint', validateBody(yourSchema), handler);
```

### Caching Pattern
```javascript
// Use appropriate cache service
const cacheService = require('../services/cacheService');
const dashboardCacheService = require('../services/dashboardCacheService');

// Get cached data
const stats = await dashboardCacheService.getDashboardStats(models);

// Invalidate cache after data changes
dashboardCacheService.invalidateUserCaches();
```

---

## 🚨 Common Issues & Solutions

### Authentication Issues
```javascript
// Problem: User not authenticated
// Check: req.user exists and user.status === 'approved'

// Problem: Admin access required
// Use: ensureAdmin middleware

// Problem: Password reset not working
// Check: Email service configuration in .env
```

### Database Issues
```javascript
// Problem: Validation errors
// Check: Joi schemas in src/validators/

// Problem: Reference errors
// Ensure: populate() calls for ObjectId references

// Problem: Index errors
// Run: node scripts/verify-indexes.js
```

### Cache Issues
```javascript
// Problem: Stale data
// Solution: Check cache invalidation in relevant routes

// Problem: Cache misses
// Check: TTL values and cache key consistency

// Debug: Use /api/cache/stats endpoint
```

### Steam Integration Issues
```javascript
// Problem: Steam search not working
// Check: Internet connectivity, Steam API status

// Problem: Game data not updating
// Check: steamAppId assignment and cache invalidation

// Debug: Test with node testSteamIntegration.js
```

---

## 📚 Key Documentation References

### Architecture Documentation
- **docs/architecture/caching-system.md** - Multi-tier caching implementation
- **docs/architecture/error-handling.md** - Centralized error handling
- **docs/architecture/validation-system.md** - Joi validation system

### Feature Documentation
- **docs/features/steam-integration.md** - Steam API integration details
- **docs/features/user-approval-system.md** - User registration workflow
- **docs/features/super-admin-system.md** - Admin privilege system
- **docs/features/health-monitoring.md** - System health monitoring

### Deployment Documentation
- **docs/deployment/docker-deployment.md** - Docker deployment guide
- **SAFE_DEPLOYMENT_GUIDE.md** - Safe production deployment
- **docs/troubleshooting/troubleshooting.md** - Common issues and solutions

### Testing Documentation
- **tests/README.md** - Comprehensive test suite (110+ tests)

---

## 🎯 Common AI Agent Tasks

### Code Analysis Tasks
```bash
# Understand a feature
1. Read relevant docs/features/*.md
2. Examine src/models/ for data structure
3. Check src/routes/ for API endpoints
4. Review src/services/ for business logic

# Debug an issue
1. Check docs/troubleshooting/troubleshooting.md
2. Review error logs and patterns
3. Check src/middleware/errorHandler.js
4. Use health endpoints: /api/health
```

### Development Tasks
```bash
# Add new feature
1. Design data model (src/models/)
2. Create validation schema (src/validators/)
3. Implement service logic (src/services/)
4. Create routes (src/routes/)
5. Add tests (tests/)
6. Update documentation

# Fix bugs
1. Identify error pattern
2. Check related middleware
3. Review validation rules
4. Test with existing test suite
```

### Deployment Tasks
```bash
# Safe deployment
1. Use safe-deploy-update.sh script
2. Check health endpoints after deployment
3. Monitor logs for errors
4. Verify cache functionality

# Troubleshooting
1. Check container status: docker compose ps
2. Review logs: docker compose logs
3. Test health: curl /api/health
4. Check database connectivity
```

---

## 🔧 Environment & Configuration

### Key Environment Variables
```bash
# Database
MONGO_URI=mongodb://localhost:27017/gameplan
MONGO_PASSWORD=secure_password

# Authentication
SESSION_SECRET=secure_session_secret

# Admin Setup
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD=secure_admin_password

# External APIs (optional)
RAWG_API_KEY=your_rawg_api_key
# Note: Steam API works without key

# Email (for password reset)
EMAIL_HOST=smtp.gmail.com
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password

# Environment
NODE_ENV=production|development
PORT=3000
```

### Development vs Production
- **Development**: Auto-login enabled, detailed errors, debug logging
- **Production**: Security hardened, sanitized errors, optimized caching

---

## 🎯 Success Indicators

### Application is Working When:
- ✅ Health endpoint returns `{"status":"healthy"}`
- ✅ Users can register and get approved
- ✅ Events can be created and joined
- ✅ Steam integration shows game data
- ✅ Cache hit rates > 70%
- ✅ No critical errors in logs

### Common Success Patterns:
- User registration → admin approval → event creation → participation
- Game search → selection → event creation → Steam integration
- Cache warming → improved performance → reduced API calls

---

## 📋 Quick Reference Commands

### Health Checks
```bash
curl http://localhost:3000/api/health
curl http://localhost:3000/api/health?detailed=true
curl http://localhost:3000/api/cache/stats
```

### Database Operations
```bash
node scripts/verify-indexes.js
node scripts/index-maintenance.js analyze
node scripts/createAdmin.js
```

### Testing
```bash
npm test                    # Run all tests
npm test tests/unit/        # Unit tests only
npm test tests/integration/ # Integration tests
```

### Docker Operations
```bash
docker compose ps           # Check container status
docker compose logs -f      # Follow logs
docker compose restart     # Restart services
```

---

## 📝 Documentation Maintenance Responsibilities

### **CRITICAL**: Always Update Documentation When Making Changes

As an AI agent working on GamePlan, you are responsible for maintaining the accuracy and currency of ALL documentation. This ensures future AI agents and developers have accurate information.

### **Documentation Update Matrix**

| **Type of Change** | **Files to Update** | **Priority** |
|-------------------|-------------------|-------------|
| **New Features** | AI-AGENT-GUIDE.md + docs/features/*.md + README.md | 🔴 Critical |
| **API Changes** | AI-AGENT-GUIDE.md + docs/architecture/*.md | 🔴 Critical |
| **Data Model Changes** | AI-AGENT-GUIDE.md + docs/schemas/*.md | 🔴 Critical |
| **Architecture Changes** | AI-AGENT-GUIDE.md + docs/architecture/*.md | 🔴 Critical |
| **Deployment Changes** | docs/deployment/*.md + SAFE_DEPLOYMENT_GUIDE.md | 🔴 Critical |
| **Route/Endpoint Changes** | AI-AGENT-GUIDE.md + relevant feature docs | 🟡 Important |
| **Bug Fixes** | docs/troubleshooting/*.md (if applicable) | 🟢 Optional |

### **Documentation Update Workflow**

#### **Step 1: Identify Documentation Impact**
Before making any code changes, ask yourself:
- Does this change affect system architecture?
- Are new features being added?
- Do data models change?
- Are new routes/endpoints added?
- Does deployment process change?

#### **Step 2: Update AI-AGENT-GUIDE.md First**
If your changes affect:
- System architecture → Update "System Architecture Overview"
- Data models → Update "Data Models & Relationships" 
- Routes → Update "Codebase Structure Map"
- Workflows → Update "User Journeys & Workflows"
- Common patterns → Update "Development Patterns"

#### **Step 3: Update Specific Documentation**
- **New Features**: Create or update docs/features/[feature-name].md
- **Architecture Changes**: Update docs/architecture/[relevant-system].md
- **Deployment Changes**: Update docs/deployment/[relevant-guide].md
- **API Changes**: Update relevant route documentation

#### **Step 4: Verify Cross-References**
- Check all links still work
- Ensure examples are still accurate
- Verify code snippets match current implementation
- Update version numbers and timestamps

### **Documentation Quality Standards**

#### **Maintain These Standards:**
✅ **Accuracy** - All information must reflect current code state
✅ **Completeness** - Cover all aspects of changes made
✅ **Consistency** - Follow existing documentation patterns
✅ **Clarity** - Write for both humans and AI agents
✅ **Cross-References** - Link related documentation appropriately

#### **Required Elements for Updates:**
- Clear section headers with emojis (following existing pattern)
- Code examples where applicable
- Step-by-step procedures
- Troubleshooting information
- Links to related documentation
- Updated timestamps

### **Specific Update Scenarios**

#### **Adding New Routes/Endpoints**
1. Update AI-AGENT-GUIDE.md "Codebase Structure Map"
2. Add route to appropriate docs/features/*.md
3. Update any workflow documentation
4. Add to troubleshooting if complex

#### **Modifying Data Models**
1. Update AI-AGENT-GUIDE.md "Data Models & Relationships"
2. Update docs/schemas/ if schema docs exist
3. Update any feature docs that reference the model
4. Update migration documentation if applicable

#### **Adding New Features**
1. Create new docs/features/[feature-name].md
2. Update AI-AGENT-GUIDE.md with feature overview
3. Update README.md feature list
4. Update docs/README.md with new documentation link
5. Add to relevant workflow documentation

#### **Architecture Changes**
1. Update AI-AGENT-GUIDE.md architecture sections
2. Update docs/architecture/[relevant-system].md
3. Update deployment docs if infrastructure changes
4. Update troubleshooting docs for new failure modes

### **Documentation Validation Checklist**

Before completing any task, verify:
- [ ] All affected documentation files have been updated
- [ ] Code examples match current implementation
- [ ] Links and cross-references work correctly
- [ ] Timestamps have been updated
- [ ] New features are documented completely
- [ ] Troubleshooting information is current
- [ ] AI-AGENT-GUIDE.md reflects all changes

### **Emergency Documentation Updates**

If you discover outdated documentation during your work:
1. **Immediately note the discrepancy**
2. **Update the incorrect information**
3. **Check for similar issues in related docs**
4. **Add a note about what was corrected**

### **Documentation Maintenance Commands**

```bash
# Before making changes - review current docs
find docs/ -name "*.md" -exec grep -l "keyword" {} \;

# After making changes - verify links
# (Add link checking to your workflow)

# Update timestamps
sed -i 's/Last Updated: .*/Last Updated: $(date +"%B %Y")/' *.md
```

---

**Remember**: This application prioritizes user experience, security, and performance. Always consider the impact on users when making changes, and use the comprehensive test suite to verify functionality.

**DOCUMENTATION RESPONSIBILITY**: As an AI agent, you are a steward of this project's documentation. Keep it accurate, current, and helpful for future AI agents and developers.

**Last Updated**: January 2025
**For AI Agents**: Read this guide first, then reference specific documentation as needed. ALWAYS update relevant documentation when making changes.
