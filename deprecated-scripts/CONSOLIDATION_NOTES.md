# Script Consolidation Notes

## Date: 2025-06-22

## Summary
Multiple script versions have been consolidated to reduce confusion and maintain only the best, most robust versions.

## Actions Taken

### 1. Deploy Update Scripts
**Consolidated from 3 versions to 1:**
- ❌ `deploy-update.sh` (original) → moved to `deprecated-scripts/deploy-update-original.sh`
- ❌ `deploy-update-enhanced.sh` → moved to `deprecated-scripts/deploy-update-enhanced.sh`
- ✅ `deploy-update-enhanced-fixed.sh` → **renamed to `deploy-update.sh`** (ACTIVE)

**Why the "enhanced-fixed" version was chosen:**
- Contains all features from basic and enhanced versions
- Includes pre-flight validation and configuration healing
- Has improved git handling (uses `git reset --hard` instead of `git pull`)
- Better error handling and rollback capabilities
- Most comprehensive and robust version

### 2. GamePlan Deploy Scripts
**Consolidated from 2 versions to 1:**
- ❌ `gameplan-deploy.sh` (original) → moved to `deprecated-scripts/gameplan-deploy-original.sh`
- ✅ `gameplan-deploy-fixed.sh` → **renamed to `gameplan-deploy.sh`** (ACTIVE)

**Why the "fixed" version was chosen:**
- Fixes password generation issues (uses alphanumeric instead of base64)
- Properly handles production compose files
- Better error handling and validation
- More robust deployment process

### 3. Backup Scripts
**Kept both versions for cross-platform compatibility:**
- ✅ `backup-local.sh` (Linux/macOS/WSL)
- ✅ `backup-local.ps1` (Windows PowerShell)

## Current Active Scripts

| Script Name | Purpose | Platform |
|-------------|---------|----------|
| `deploy-update.sh` | Safe application updates with rollback | Linux/macOS/WSL |
| `gameplan-deploy.sh` | Complete deployment from scratch | Linux/macOS/WSL |
| `backup-local.sh` | Local development backup | Linux/macOS/WSL |
| `backup-local.ps1` | Local development backup | Windows PowerShell |

## Benefits Achieved

1. **Reduced Confusion** - No more guessing which script version to use
2. **Maintained Best Functionality** - Kept the most robust and feature-complete versions
3. **Preserved Cross-Platform Support** - Both bash and PowerShell backup scripts retained
4. **Easier Maintenance** - Fewer files to maintain and update
5. **Better User Experience** - Clear, single-purpose scripts

## Recovery

If you need to restore any deprecated script:
```bash
# Copy back from deprecated folder
cp deprecated-scripts/deploy-update-original.sh deploy-update-original.sh
```

## Recommendations

1. Test the consolidated scripts to ensure they work as expected
2. Update any documentation that references the old script names
3. Consider removing the deprecated-scripts folder after confirming everything works
4. Update any CI/CD pipelines or automation that might reference the old script names
