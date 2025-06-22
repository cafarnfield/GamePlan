# User Approval System

GamePlan includes a comprehensive user approval system that requires admin approval for all new user registrations, providing enhanced security, user management capabilities, and detailed audit logging.

## Overview

The user approval system ensures that all new registrations are reviewed by administrators before users can access the platform. This provides security, quality control, and comprehensive user management capabilities.

## Key Features

### 1. User Registration Flow
- **Pending Status**: All new users register with "pending" status
- **CAPTCHA Protection**: Optional reCAPTCHA integration to prevent spam registrations
- **IP Tracking**: Registration IP addresses are logged for security analysis
- **Email Validation**: Prevents duplicate registrations and rejected email reuse
- **Approval Required**: Users cannot log in until approved by an admin

### 2. Admin Dashboard
- **Comprehensive Statistics**: User counts, approval rates, registration analytics
- **Suspicious Activity Detection**: Identifies multiple registrations from same IP
- **Recent Activity Log**: Tracks all admin actions with timestamps
- **Quick Actions**: Direct links to pending user reviews and bulk operations

### 3. User Management Interface
- **Advanced Filtering**: Filter users by status (pending, approved, rejected, blocked, probation)
- **Bulk Operations**: Approve, reject, or delete multiple users at once
- **Search Functionality**: Search by name, email, or game nickname
- **Status Badges**: Visual indicators for user status and roles
- **Detailed User Information**: Registration date, IP address, approval notes

### 4. Approval Actions
- **Approve**: Grants user access to the platform
- **Reject**: Denies access and prevents future registration with same email
- **Delete**: Removes user from system entirely
- **Block/Unblock**: Temporarily disable user access
- **Probationary Period**: Set time-limited restrictions on new users

### 5. Audit Logging
- **Complete Action History**: All admin actions are logged with timestamps
- **User Context**: Tracks which admin performed which actions
- **Bulk Action Support**: Special handling for bulk operations
- **IP Address Logging**: Security tracking for admin actions
- **Notes and Reasons**: Optional notes for approval/rejection decisions

## User Statuses

### Pending
- Default status for new registrations
- Cannot log in to the platform
- Visible to admins for review
- Can be approved, rejected, or deleted

### Approved
- Full access to platform features
- Can create and join events
- May have probationary restrictions if recently approved

### Rejected
- Cannot log in to the platform
- Email address is blacklisted from future registrations
- Can be re-approved by admins if needed

### Blocked
- Temporarily suspended from platform access
- Can be unblocked by admins
- Maintains user data and event history

## Admin Interface Navigation

### Main Admin Panel (`/admin`)
- Game management
- Steam integration tools
- Quick access to user management

### Admin Dashboard (`/admin/dashboard`)
- System overview and statistics
- Suspicious activity alerts
- Recent admin activity log
- Advanced user search

### User Management (`/admin/users`)
- Complete user listing with filters
- Individual user actions (approve, reject, block, delete)
- Bulk operations for multiple users
- Real-time search and filtering

## Security Features

### Registration Protection
- **reCAPTCHA Integration**: Prevents automated registrations
- **IP Address Tracking**: Identifies suspicious registration patterns
- **Email Blacklisting**: Prevents rejected users from re-registering
- **Duplicate Prevention**: Blocks multiple accounts with same email

### Admin Audit Trail
- **Complete Action Logging**: Every admin action is recorded
- **IP Address Tracking**: Security monitoring for admin activities
- **Timestamp Tracking**: Precise timing of all actions
- **Bulk Action Details**: Special handling for mass operations

### Access Control
- **Admin-Only Routes**: User management restricted to administrators
- **Session Management**: Secure authentication and authorization
- **Development Mode**: Special auto-login for development environments

## Configuration

### Environment Variables

```bash
# reCAPTCHA configuration (optional - leave empty to disable)
RECAPTCHA_SITE_KEY=your_recaptcha_site_key
RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key

# Development mode settings
NODE_ENV=development
AUTO_LOGIN_ADMIN=true  # Only for development
```

### reCAPTCHA Setup
1. Visit [Google reCAPTCHA](https://www.google.com/recaptcha/)
2. Create a new site with reCAPTCHA v2 "I'm not a robot" checkbox
3. Add your domain to the site settings
4. Copy the Site Key and Secret Key to your `.env` file

## Database Models

### User Model Extensions
```javascript
{
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected'], 
    default: 'pending' 
  },
  registrationIP: String,
  approvedAt: Date,
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approvalNotes: String,
  rejectedAt: Date,
  rejectedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  rejectedReason: String,
  probationaryUntil: Date,
  isBlocked: { type: Boolean, default: false }
}
```

### Audit Log Model
```javascript
{
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  adminName: { type: String, required: true },
  action: { type: String, required: true },
  targetUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  targetUserEmail: String,
  targetUserName: String,
  notes: String,
  ipAddress: String,
  bulkCount: { type: Number, default: 1 },
  details: mongoose.Schema.Types.Mixed,
  timestamp: { type: Date, default: Date.now }
}
```

### Rejected Email Model
```javascript
{
  email: { type: String, required: true, unique: true, lowercase: true },
  rejectedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  reason: String,
  rejectedAt: { type: Date, default: Date.now }
}
```

## API Endpoints

### User Management
- `GET /admin/users` - List users with filtering
- `POST /admin/user/approve/:id` - Approve user
- `POST /admin/user/reject/:id` - Reject user
- `POST /admin/user/delete/:id` - Delete user
- `POST /admin/user/block/:id` - Block user
- `POST /admin/user/unblock/:id` - Unblock user
- `POST /admin/user/toggle-admin/:id` - Toggle admin status
- `POST /admin/user/end-probation/:id` - End probationary period

### Bulk Operations
- `POST /admin/users/bulk-approve` - Bulk approve users
- `POST /admin/users/bulk-reject` - Bulk reject users
- `POST /admin/users/bulk-delete` - Bulk delete users

### Analytics
- `GET /api/admin/pending-count` - Get pending user count
- `GET /admin/dashboard` - Admin dashboard with statistics

## Usage Examples

### Approving a User
1. Navigate to `/admin/users?filter=pending`
2. Click "Approve" button for the user
3. Optionally add approval notes
4. Click "Confirm" to approve

### Bulk Operations
1. Navigate to `/admin/users`
2. Select multiple users using checkboxes
3. Choose bulk action (approve, reject, delete)
4. Add optional notes
5. Confirm the action

### Monitoring Suspicious Activity
1. Visit `/admin/dashboard`
2. Check "IP Analytics" section for suspicious patterns
3. Review users from flagged IP addresses
4. Take appropriate action (approve, reject, or investigate)

## Best Practices

### User Review Process
1. **Check Registration Details**: Verify name, email, and game nickname
2. **Review IP Address**: Look for suspicious patterns or known problematic IPs
3. **Add Notes**: Document approval/rejection reasons for future reference
4. **Monitor Probationary Users**: Keep track of newly approved users

### Security Considerations
1. **Regular Audit Reviews**: Periodically review admin activity logs
2. **IP Address Monitoring**: Watch for unusual registration patterns
3. **Rejected Email Management**: Regularly review and clean up rejected email list
4. **Admin Access Control**: Limit admin privileges to trusted users only

### Performance Optimization
1. **Bulk Operations**: Use bulk actions for processing multiple users
2. **Filtering**: Use status filters to focus on relevant users
3. **Search Functionality**: Use search to quickly find specific users
4. **Regular Cleanup**: Periodically clean up old rejected users and audit logs

## Troubleshooting

### Common Issues

#### Users Can't Register
- Check if reCAPTCHA is properly configured
- Verify email isn't in rejected list
- Check for duplicate email addresses

#### Admin Can't Access User Management
- Verify user has admin privileges
- Check authentication status
- Review server logs for errors

#### Bulk Operations Not Working
- Ensure users are selected with checkboxes
- Check network connectivity
- Review browser console for JavaScript errors

### Error Messages
- "This email address has been rejected" - Email is blacklisted
- "Please complete the CAPTCHA verification" - reCAPTCHA failed
- "Your account is pending admin approval" - User not yet approved
- "Your account has been rejected" - User was rejected by admin

## Future Enhancements

### Planned Features
1. **Email Notifications**: Notify users of approval/rejection status
2. **Advanced Analytics**: More detailed registration and approval analytics
3. **Automated Approval Rules**: Rule-based auto-approval for trusted domains
4. **User Communication**: Built-in messaging system for admin-user communication
5. **Export Functionality**: Export user lists and audit logs
6. **Advanced Filtering**: More granular filtering options
7. **Role-Based Permissions**: Different admin permission levels

### Integration Opportunities
1. **External Authentication**: Integration with OAuth providers
2. **Spam Detection**: Advanced spam detection algorithms
3. **Geolocation**: Location-based registration analysis
4. **Machine Learning**: Automated suspicious activity detection

## Related Documentation

- [Admin Dashboard](../features/admin-dashboard.md) - Admin interface overview
- [Security Features](../operations/security.md) - Security implementation details
- [User Management](../operations/user-management.md) - User administration
- [Audit Logging](../operations/audit-logging.md) - Audit trail documentation

## Support

For issues or questions regarding the user approval system:
1. Check the troubleshooting section above
2. Review server logs for error messages
3. Verify configuration settings in `.env` file
4. Test with development mode enabled for debugging

## Changelog

### Version 1.0.0
- Initial implementation of user approval system
- Admin dashboard with statistics and analytics
- Comprehensive user management interface
- Audit logging system
- reCAPTCHA integration
- Bulk operations support
- IP address tracking and analysis
- Rejected email blacklisting
- Probationary user support
