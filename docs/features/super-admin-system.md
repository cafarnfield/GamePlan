# Super Admin System

The GamePlan application implements a hierarchical admin system with Super Admin privileges that provide enhanced security and control over admin operations.

## Overview

The super admin system creates a secure hierarchy of user privileges, ensuring that administrative operations are properly controlled and audited while preventing unauthorized privilege escalation.

## User Hierarchy

### 1. Regular Users
- Standard application users
- Can create events, join events, manage their own profile
- No administrative privileges

### 2. Admins (🛡️)
- Can approve/reject user registrations
- Can manage regular users (block, unblock, delete)
- Can manage games and events
- **Cannot modify other admins**

### 3. Super Admins (👑)
- All admin privileges
- Can promote users to admin
- Can promote admins to super admin
- Can demote super admins to admin
- Can delete/block/modify admin users
- **Cannot delete super admins directly** (must demote first)

### 4. Protected Users (🔥)
- Special protection level (designed for system-critical accounts)
- Cannot be deleted by anyone
- Cannot be modified by anyone except themselves
- Always remains protected super admin

## Key Security Features

### Admin Protection Rules
- **Regular admins cannot modify other admins** - Only super admins can perform operations on admin users
- **Super admin deletion protection** - Super admins must be demoted to admin before deletion
- **Protected user immunity** - Protected users cannot be modified by anyone except themselves

### Confirmation Requirements
- **Double confirmation for super admin demotion** - Extra security step to prevent accidental privilege removal
- **Clear warning messages** - Users are informed about the consequences of privilege changes
- **Enhanced audit logging** - All super admin operations are logged with detailed information

## Database Schema

### User Model Updates
```javascript
{
  isAdmin: Boolean,           // Existing admin field
  isSuperAdmin: Boolean,      // Super admin privileges
  isProtected: Boolean        // Protected user status
}
```

### Default Values
For existing users:
- `isSuperAdmin: false`
- `isProtected: false`

## Implementation Details

### New API Endpoints
- `POST /admin/user/promote-super-admin/:id` - Promote admin to super admin
- `POST /admin/user/demote-super-admin/:id` - Demote super admin to admin

### Enhanced Middleware
- `ensureSuperAdmin()` - Requires super admin privileges
- `checkAdminOperationPermission()` - Protects admin-targeting operations

### UI Enhancements
- Visual badges for different privilege levels
- Conditional button rendering based on user privileges
- Enhanced confirmation dialogs
- Clear error messages for insufficient privileges

## Setup Instructions

### 1. Initial Super Admin Setup
Run the setup script to configure initial super admins:
```bash
node setupSuperAdmins.js
```

This script will:
- Look for system users and set appropriate privileges
- Set protected status for critical accounts
- Display current admin status
- Create initial super admin if none exist

### 2. Manual Super Admin Creation
If you need to manually create a super admin:

#### Via Admin Interface
1. Ensure the user is an admin first
2. Use the admin interface to promote them to super admin
3. Confirm the promotion action

#### Via Database
```javascript
await User.findOneAndUpdate(
  { email: 'user@example.com' },
  { isAdmin: true, isSuperAdmin: true }
);
```

### 3. Setting Protected Status
For system-critical accounts:
```javascript
await User.findOneAndUpdate(
  { email: 'critical@example.com' },
  { 
    isAdmin: true, 
    isSuperAdmin: true, 
    isProtected: true 
  }
);
```

## Operational Guidelines

### Creating Super Admins
1. **User must be an admin first** - Cannot promote regular users directly
2. **Only existing super admins can promote** - Prevents unauthorized escalation
3. **Consider security implications** - Super admin access should be limited

### Removing Super Admin Privileges
1. **Super admins cannot demote themselves** - Prevents accidental lockout
2. **Requires double confirmation** - Extra security step
3. **User remains as regular admin** - Maintains some administrative access
4. **Protected users cannot be demoted** - System protection

### Managing Protected Users
1. **Only the protected user can modify their account** - Ultimate protection
2. **Protected status cannot be removed by others** - Permanent protection
3. **Designed for system-critical accounts** - Use sparingly

## Security Considerations

### Privilege Escalation Prevention
- Regular admins cannot elevate their own privileges
- Super admin promotion requires existing super admin approval
- Protected users have ultimate immunity from modification

### Audit Trail
All super admin operations are logged with:
- Who performed the action
- What action was performed
- Target user information
- Timestamp and IP address
- Additional context and notes

### Best Practices
1. **Limit super admin accounts** - Only grant to trusted users
2. **Regular privilege review** - Periodically audit admin privileges
3. **Use protected status sparingly** - Only for system-critical accounts
4. **Monitor audit logs** - Review admin activity regularly
5. **Document privilege changes** - Maintain records of why privileges were granted/revoked

## Usage Examples

### Promoting User to Super Admin
1. Navigate to `/admin/users`
2. Find the admin user to promote
3. Click "Promote to Super Admin"
4. Confirm the action in the dialog
5. User now has super admin privileges

### Demoting Super Admin
1. Navigate to `/admin/users`
2. Find the super admin to demote
3. Click "Demote Super Admin"
4. Confirm twice (double confirmation required)
5. User is now a regular admin

### Checking User Privileges
```javascript
// Check if user is super admin
if (user.isSuperAdmin) {
  // Allow super admin operations
}

// Check if user is protected
if (user.isProtected) {
  // Prevent modifications
}
```

## Troubleshooting

### Common Issues

#### "Super Admin privileges required"
- User needs super admin status to perform the operation
- Check user's `isSuperAdmin` field in database
- Ensure user is logged in with correct account

#### "This user is protected"
- Attempting to modify a protected user
- Only the protected user themselves can make changes
- Check `isProtected` field in database

#### "Cannot delete Super Admin directly"
- Must demote super admin to admin before deletion
- Use the demotion process first
- Then proceed with deletion if needed

### Recovery Procedures

#### Lost Super Admin Access
1. **Database method**: Update user directly in MongoDB
   ```javascript
   db.users.updateOne(
     { email: 'admin@example.com' },
     { $set: { isAdmin: true, isSuperAdmin: true } }
   );
   ```

2. **Setup script**: Run the super admin setup script
   ```bash
   node setupSuperAdmins.js
   ```

3. **Development mode**: Use mock admin user if available

#### Locked Out of System
1. Check for protected users in database
2. Use database console to grant super admin privileges
3. Review audit logs to understand what happened
4. Implement additional safeguards if needed

## API Reference

### Super Admin Endpoints

#### Promote to Super Admin
```http
POST /admin/user/promote-super-admin/:id
Authorization: Required (Super Admin)
```

#### Demote Super Admin
```http
POST /admin/user/demote-super-admin/:id
Authorization: Required (Super Admin)
```

### Response Format
```json
{
  "success": true,
  "message": "User promoted to super admin successfully",
  "user": {
    "id": "user_id",
    "email": "user@example.com",
    "isAdmin": true,
    "isSuperAdmin": true,
    "isProtected": false
  }
}
```

## Future Enhancements

### Planned Features
1. **Role-based permissions** - More granular than admin/super admin
2. **Time-limited super admin privileges** - Temporary elevated access
3. **Multi-factor authentication** - Additional security for super admin operations
4. **Advanced audit reporting** - Detailed privilege change tracking
5. **Privilege request system** - Formal process for requesting admin access

### Integration Opportunities
1. **External authentication** - Integration with enterprise identity systems
2. **Automated privilege review** - Regular auditing and cleanup
3. **Risk-based access control** - Dynamic privilege adjustment based on behavior
4. **Compliance reporting** - Automated compliance and audit reports

## Related Documentation

- [User Approval System](../features/user-approval-system.md) - User registration and approval
- [Admin Dashboard](../features/admin-dashboard.md) - Admin interface overview
- [Security Features](../operations/security.md) - Security implementation details
- [Audit Logging](../operations/audit-logging.md) - Audit trail documentation

## Support

For issues or questions regarding the super admin system:
1. Check the troubleshooting section above
2. Review audit logs for privilege changes
3. Verify user privileges in database
4. Use setup script to restore default configuration

The super admin system provides a robust foundation for secure admin management while maintaining the flexibility to expand privileges as needed.
