/**
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       properties:
 *         _id:
 *           $ref: '#/components/schemas/ObjectId'
 *         name:
 *           type: string
 *           example: "John Doe"
 *         email:
 *           type: string
 *           format: email
 *           example: "john.doe@example.com"
 *         gameNickname:
 *           type: string
 *           example: "JohnGamer123"
 *         isAdmin:
 *           type: boolean
 *           example: false
 *         isSuperAdmin:
 *           type: boolean
 *           example: false
 *         isProtected:
 *           type: boolean
 *           example: false
 *         isBlocked:
 *           type: boolean
 *           example: false
 *         status:
 *           $ref: '#/components/schemas/UserStatus'
 *         approvalNotes:
 *           type: string
 *           example: "User approved after verification"
 *         rejectedReason:
 *           type: string
 *           example: ""
 *         registrationIP:
 *           type: string
 *           example: "192.168.1.1"
 *         probationaryUntil:
 *           type: string
 *           format: date-time
 *           nullable: true
 *           example: "2024-01-01T00:00:00.000Z"
 *         createdAt:
 *           type: string
 *           format: date-time
 *           example: "2023-12-01T10:30:00.000Z"
 *         approvedAt:
 *           type: string
 *           format: date-time
 *           nullable: true
 *           example: "2023-12-01T11:00:00.000Z"
 *         approvedBy:
 *           $ref: '#/components/schemas/ObjectId'
 *     
 *     UserRegistration:
 *       type: object
 *       required:
 *         - name
 *         - email
 *         - password
 *         - g-recaptcha-response
 *       properties:
 *         name:
 *           type: string
 *           minLength: 2
 *           maxLength: 50
 *           example: "John Doe"
 *         email:
 *           type: string
 *           format: email
 *           example: "john.doe@example.com"
 *         password:
 *           type: string
 *           minLength: 6
 *           example: "securePassword123"
 *         gameNickname:
 *           type: string
 *           maxLength: 30
 *           example: "JohnGamer123"
 *         g-recaptcha-response:
 *           type: string
 *           description: "reCAPTCHA response token"
 *           example: "03AGdBq25..."
 *     
 *     UserLogin:
 *       type: object
 *       required:
 *         - email
 *         - password
 *       properties:
 *         email:
 *           type: string
 *           format: email
 *           example: "john.doe@example.com"
 *         password:
 *           type: string
 *           example: "securePassword123"
 *     
 *     UserProfile:
 *       type: object
 *       properties:
 *         _id:
 *           $ref: '#/components/schemas/ObjectId'
 *         name:
 *           type: string
 *           example: "John Doe"
 *         email:
 *           type: string
 *           format: email
 *           example: "john.doe@example.com"
 *         gameNickname:
 *           type: string
 *           example: "JohnGamer123"
 *         isAdmin:
 *           type: boolean
 *           example: false
 *         isSuperAdmin:
 *           type: boolean
 *           example: false
 *         status:
 *           $ref: '#/components/schemas/UserStatus'
 *         probationaryUntil:
 *           type: string
 *           format: date-time
 *           nullable: true
 *           example: null
 *         createdAt:
 *           type: string
 *           format: date-time
 *           example: "2023-12-01T10:30:00.000Z"
 *     
 *     UserProfileUpdate:
 *       type: object
 *       required:
 *         - gameNickname
 *       properties:
 *         gameNickname:
 *           type: string
 *           maxLength: 30
 *           example: "NewGamerTag123"
 *     
 *     AdminUserView:
 *       type: object
 *       properties:
 *         _id:
 *           $ref: '#/components/schemas/ObjectId'
 *         name:
 *           type: string
 *           example: "John Doe"
 *         email:
 *           type: string
 *           format: email
 *           example: "john.doe@example.com"
 *         gameNickname:
 *           type: string
 *           example: "JohnGamer123"
 *         isAdmin:
 *           type: boolean
 *           example: false
 *         isSuperAdmin:
 *           type: boolean
 *           example: false
 *         isProtected:
 *           type: boolean
 *           example: false
 *         isBlocked:
 *           type: boolean
 *           example: false
 *         status:
 *           $ref: '#/components/schemas/UserStatus'
 *         approvalNotes:
 *           type: string
 *           example: "User approved after verification"
 *         rejectedReason:
 *           type: string
 *           example: ""
 *         registrationIP:
 *           type: string
 *           example: "192.168.1.1"
 *         probationaryUntil:
 *           type: string
 *           format: date-time
 *           nullable: true
 *           example: "2024-01-01T00:00:00.000Z"
 *         createdAt:
 *           type: string
 *           format: date-time
 *           example: "2023-12-01T10:30:00.000Z"
 *         approvedAt:
 *           type: string
 *           format: date-time
 *           nullable: true
 *           example: "2023-12-01T11:00:00.000Z"
 *         approvedBy:
 *           $ref: '#/components/schemas/ObjectId'
 *     
 *     UserApprovalRequest:
 *       type: object
 *       properties:
 *         notes:
 *           type: string
 *           maxLength: 500
 *           example: "User verified and approved for access"
 *     
 *     UserRejectionRequest:
 *       type: object
 *       required:
 *         - notes
 *       properties:
 *         notes:
 *           type: string
 *           minLength: 1
 *           maxLength: 500
 *           example: "Account rejected due to suspicious activity"
 *     
 *     BulkUserOperationRequest:
 *       allOf:
 *         - $ref: '#/components/schemas/BulkOperationRequest'
 *         - type: object
 *           properties:
 *             userIds:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/ObjectId'
 *               minItems: 1
 *               example: ["507f1f77bcf86cd799439011", "507f1f77bcf86cd799439012"]
 */
