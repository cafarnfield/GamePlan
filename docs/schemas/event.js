/**
 * @swagger
 * components:
 *   schemas:
 *     Extension:
 *       type: object
 *       properties:
 *         _id:
 *           $ref: '#/components/schemas/ObjectId'
 *         name:
 *           type: string
 *           example: "Enhanced Graphics Mod"
 *         downloadLink:
 *           type: string
 *           format: uri
 *           example: "https://example.com/mod-download"
 *         installationTime:
 *           type: number
 *           description: "Installation time in minutes"
 *           example: 15
 *         description:
 *           type: string
 *           example: "Improves game graphics and performance"
 *     
 *     Event:
 *       type: object
 *       properties:
 *         _id:
 *           $ref: '#/components/schemas/ObjectId'
 *         name:
 *           type: string
 *           example: "Friday Night CS2 Tournament"
 *         game:
 *           $ref: '#/components/schemas/Game'
 *         description:
 *           type: string
 *           example: "Join us for an exciting Counter-Strike 2 tournament with prizes!"
 *         playerLimit:
 *           type: number
 *           minimum: 1
 *           example: 10
 *         date:
 *           type: string
 *           format: date-time
 *           example: "2023-12-15T20:00:00.000Z"
 *         players:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/User'
 *         requiredExtensions:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/Extension'
 *         platforms:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/Platform'
 *           example: ["PC"]
 *         steamAppId:
 *           type: number
 *           nullable: true
 *           example: 730
 *         createdBy:
 *           $ref: '#/components/schemas/User'
 *         createdAt:
 *           type: string
 *           format: date-time
 *           example: "2023-12-01T10:30:00.000Z"
 *         gameStatus:
 *           type: string
 *           enum: ['approved', 'pending']
 *           example: "approved"
 *         isVisible:
 *           type: boolean
 *           example: true
 *     
 *     EventCreation:
 *       type: object
 *       required:
 *         - name
 *         - description
 *         - date
 *         - playerLimit
 *         - platforms
 *         - gameSelection
 *       properties:
 *         name:
 *           type: string
 *           minLength: 1
 *           maxLength: 100
 *           example: "Friday Night CS2 Tournament"
 *         description:
 *           type: string
 *           minLength: 1
 *           maxLength: 1000
 *           example: "Join us for an exciting Counter-Strike 2 tournament with prizes!"
 *         date:
 *           type: string
 *           format: date-time
 *           example: "2023-12-15T20:00:00.000Z"
 *         playerLimit:
 *           type: number
 *           minimum: 1
 *           maximum: 100
 *           example: 10
 *         platforms:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/Platform'
 *           minItems: 1
 *           example: ["PC"]
 *         gameSelection:
 *           type: string
 *           description: "JSON string containing game selection data"
 *           example: '{"type":"existing","gameId":"507f1f77bcf86cd799439011"}'
 *         extensions:
 *           type: string
 *           description: "JSON string containing extensions data"
 *           example: '[{"name":"Graphics Mod","downloadLink":"https://example.com","installationTime":15,"description":"Enhanced graphics"}]'
 *     
 *     EventUpdate:
 *       type: object
 *       required:
 *         - name
 *         - description
 *         - date
 *         - playerLimit
 *         - platforms
 *       properties:
 *         name:
 *           type: string
 *           minLength: 1
 *           maxLength: 100
 *           example: "Updated Tournament Name"
 *         gameId:
 *           $ref: '#/components/schemas/ObjectId'
 *         description:
 *           type: string
 *           minLength: 1
 *           maxLength: 1000
 *           example: "Updated event description"
 *         date:
 *           type: string
 *           format: date-time
 *           example: "2023-12-15T21:00:00.000Z"
 *         playerLimit:
 *           type: number
 *           minimum: 1
 *           maximum: 100
 *           example: 12
 *         platforms:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/Platform'
 *           minItems: 1
 *           example: ["PC", "PlayStation"]
 *         extensions:
 *           type: string
 *           description: "JSON string containing extensions data"
 *           example: '[]'
 *     
 *     EventDuplication:
 *       type: object
 *       required:
 *         - name
 *         - date
 *         - playerLimit
 *         - platforms
 *       properties:
 *         name:
 *           type: string
 *           minLength: 1
 *           maxLength: 100
 *           example: "Duplicated Tournament"
 *         description:
 *           type: string
 *           maxLength: 1000
 *           example: "Duplicated event description"
 *         date:
 *           type: string
 *           format: date-time
 *           example: "2023-12-22T20:00:00.000Z"
 *         playerLimit:
 *           type: number
 *           minimum: 1
 *           maximum: 100
 *           example: 10
 *         platforms:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/Platform'
 *           minItems: 1
 *           example: ["PC"]
 *         copy-extensions:
 *           type: boolean
 *           description: "Whether to copy extensions from original event"
 *           example: true
 *     
 *     EventSummary:
 *       type: object
 *       properties:
 *         _id:
 *           $ref: '#/components/schemas/ObjectId'
 *         name:
 *           type: string
 *           example: "Friday Night CS2 Tournament"
 *         game:
 *           type: object
 *           properties:
 *             _id:
 *               $ref: '#/components/schemas/ObjectId'
 *             name:
 *               type: string
 *               example: "Counter-Strike 2"
 *             status:
 *               $ref: '#/components/schemas/GameStatus'
 *         date:
 *           type: string
 *           format: date-time
 *           example: "2023-12-15T20:00:00.000Z"
 *         playerLimit:
 *           type: number
 *           example: 10
 *         currentPlayers:
 *           type: number
 *           example: 7
 *         createdBy:
 *           type: object
 *           properties:
 *             _id:
 *               $ref: '#/components/schemas/ObjectId'
 *             name:
 *               type: string
 *               example: "John Doe"
 *             gameNickname:
 *               type: string
 *               example: "JohnGamer123"
 *         gameStatus:
 *           type: string
 *           enum: ['approved', 'pending']
 *           example: "approved"
 *         isVisible:
 *           type: boolean
 *           example: true
 *         platforms:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/Platform'
 *           example: ["PC"]
 *     
 *     BulkEventOperationRequest:
 *       allOf:
 *         - $ref: '#/components/schemas/BulkOperationRequest'
 *         - type: object
 *           properties:
 *             eventIds:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/ObjectId'
 *               minItems: 1
 *               example: ["507f1f77bcf86cd799439011", "507f1f77bcf86cd799439012"]
 */
