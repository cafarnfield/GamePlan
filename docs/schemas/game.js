/**
 * @swagger
 * components:
 *   schemas:
 *     Game:
 *       type: object
 *       properties:
 *         _id:
 *           $ref: '#/components/schemas/ObjectId'
 *         name:
 *           type: string
 *           example: "Counter-Strike 2"
 *         description:
 *           type: string
 *           example: "Tactical first-person shooter game"
 *         platforms:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/Platform'
 *           example: ["PC"]
 *         steamAppId:
 *           type: number
 *           nullable: true
 *           example: 730
 *         steamData:
 *           type: object
 *           nullable: true
 *           properties:
 *             name:
 *               type: string
 *               example: "Counter-Strike 2"
 *             short_description:
 *               type: string
 *               example: "For over two decades, Counter-Strike has offered an elite competitive experience..."
 *             header_image:
 *               type: string
 *               example: "https://cdn.akamai.steamstatic.com/steam/apps/730/header.jpg"
 *             developers:
 *               type: array
 *               items:
 *                 type: string
 *               example: ["Valve"]
 *             publishers:
 *               type: array
 *               items:
 *                 type: string
 *               example: ["Valve"]
 *         rawgId:
 *           type: number
 *           nullable: true
 *           example: 4200
 *         rawgData:
 *           type: object
 *           nullable: true
 *           properties:
 *             name:
 *               type: string
 *               example: "Counter-Strike 2"
 *             description:
 *               type: string
 *               example: "Tactical first-person shooter..."
 *             background_image:
 *               type: string
 *               example: "https://media.rawg.io/media/games/736/73619bd336c894d6941d926bfd563946.jpg"
 *             developers:
 *               type: array
 *               items:
 *                 type: string
 *               example: ["Valve Corporation"]
 *             publishers:
 *               type: array
 *               items:
 *                 type: string
 *               example: ["Valve Corporation"]
 *             genres:
 *               type: array
 *               items:
 *                 type: string
 *               example: ["Action", "Shooter"]
 *             rating:
 *               type: number
 *               example: 4.2
 *             released:
 *               type: string
 *               example: "2012-08-21"
 *         source:
 *           $ref: '#/components/schemas/GameSource'
 *         status:
 *           $ref: '#/components/schemas/GameStatus'
 *         addedBy:
 *           $ref: '#/components/schemas/ObjectId'
 *         categories:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/GameCategory'
 *           example: ["FPS", "Action"]
 *         tags:
 *           type: array
 *           items:
 *             type: string
 *           example: ["competitive", "multiplayer", "tactical"]
 *         canonicalGame:
 *           $ref: '#/components/schemas/ObjectId'
 *           nullable: true
 *         aliases:
 *           type: array
 *           items:
 *             type: string
 *           example: ["CS2", "Counter Strike 2"]
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
 *           nullable: true
 *     
 *     GameCreation:
 *       type: object
 *       required:
 *         - name
 *         - description
 *       properties:
 *         name:
 *           type: string
 *           minLength: 1
 *           maxLength: 100
 *           example: "New Awesome Game"
 *         description:
 *           type: string
 *           minLength: 1
 *           maxLength: 1000
 *           example: "An exciting new game with amazing features"
 *         imageUrl:
 *           type: string
 *           format: uri
 *           example: "https://example.com/game-image.jpg"
 *         steamAppId:
 *           type: number
 *           example: 12345
 *         categories:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/GameCategory'
 *           example: ["Action", "Adventure"]
 *     
 *     GameApprovalRequest:
 *       type: object
 *       properties:
 *         notes:
 *           type: string
 *           maxLength: 500
 *           example: "Game approved after review"
 *     
 *     GameRejectionRequest:
 *       type: object
 *       required:
 *         - notes
 *       properties:
 *         notes:
 *           type: string
 *           minLength: 1
 *           maxLength: 500
 *           example: "Game rejected due to inappropriate content"
 *     
 *     SteamGame:
 *       type: object
 *       properties:
 *         appid:
 *           type: number
 *           example: 730
 *         name:
 *           type: string
 *           example: "Counter-Strike 2"
 *         short_description:
 *           type: string
 *           example: "For over two decades, Counter-Strike has offered an elite competitive experience..."
 *         header_image:
 *           type: string
 *           example: "https://cdn.akamai.steamstatic.com/steam/apps/730/header.jpg"
 *         developers:
 *           type: array
 *           items:
 *             type: string
 *           example: ["Valve"]
 *         publishers:
 *           type: array
 *           items:
 *             type: string
 *           example: ["Valve"]
 *         price_overview:
 *           type: object
 *           nullable: true
 *           properties:
 *             currency:
 *               type: string
 *               example: "USD"
 *             initial:
 *               type: number
 *               example: 0
 *             final:
 *               type: number
 *               example: 0
 *             discount_percent:
 *               type: number
 *               example: 0
 *             initial_formatted:
 *               type: string
 *               example: ""
 *             final_formatted:
 *               type: string
 *               example: "Free To Play"
 *     
 *     RawgGame:
 *       type: object
 *       properties:
 *         id:
 *           type: number
 *           example: 4200
 *         name:
 *           type: string
 *           example: "Counter-Strike: Global Offensive"
 *         description:
 *           type: string
 *           example: "Counter-Strike: Global Offensive is a multiplayer first-person shooter..."
 *         background_image:
 *           type: string
 *           example: "https://media.rawg.io/media/games/736/73619bd336c894d6941d926bfd563946.jpg"
 *         developers:
 *           type: array
 *           items:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *           example: [{"name": "Valve Corporation"}]
 *         publishers:
 *           type: array
 *           items:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *           example: [{"name": "Valve Corporation"}]
 *         genres:
 *           type: array
 *           items:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *           example: [{"name": "Action"}, {"name": "Shooter"}]
 *         rating:
 *           type: number
 *           example: 4.2
 *         released:
 *           type: string
 *           example: "2012-08-21"
 *         platforms:
 *           type: array
 *           items:
 *             type: object
 *             properties:
 *               platform:
 *                 type: object
 *                 properties:
 *                   name:
 *                     type: string
 *           example: [{"platform": {"name": "PC"}}]
 *     
 *     GameSearchResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         results:
 *           type: array
 *           items:
 *             oneOf:
 *               - $ref: '#/components/schemas/SteamGame'
 *               - $ref: '#/components/schemas/RawgGame'
 *         total:
 *           type: number
 *           example: 25
 *         query:
 *           type: string
 *           example: "counter strike"
 *         source:
 *           type: string
 *           enum: ["steam", "rawg"]
 *           example: "steam"
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: "2023-12-01T10:30:00.000Z"
 */
