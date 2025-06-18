const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'GamePlan API Documentation',
      version: '1.0.0',
      description: `
        Comprehensive API documentation for the GamePlan gaming event management system.
        
        ## Overview
        GamePlan is a platform for organizing and managing gaming events with features including:
        - User registration and authentication with approval workflow
        - Event creation, management, and participation
        - Game database with Steam and RAWG integration
        - Administrative tools for user and content management
        - Comprehensive caching and monitoring systems
        
        ## Authentication
        This API uses session-based authentication with role-based access control:
        - **Regular Users**: Can create events, join events, manage their profile
        - **Admins**: Can manage users, approve content, access admin tools
        - **Super Admins**: Full system access including user role management
        
        ## Rate Limiting
        - Login attempts: 5 per 15 minutes per IP
        - Registration: 3 per hour per IP
        - API calls: 100 per 15 minutes per IP
        - General requests: 1000 per 15 minutes per IP
        
        ## Data Sources
        - **Steam API**: Game data integration
        - **RAWG API**: Additional game database
        - **Manual Entry**: Admin-curated game content
      `,
      contact: {
        name: 'GamePlan API Support',
        email: 'support@gameplan.local'
      },
      license: {
        name: 'ISC',
        url: 'https://opensource.org/licenses/ISC'
      }
    },
    servers: [
      {
        url: process.env.NODE_ENV === 'production' 
          ? 'https://gameplan.yourdomain.com' 
          : 'http://localhost:3000',
        description: process.env.NODE_ENV === 'production' 
          ? 'Production server' 
          : 'Development server'
      }
    ],
    components: {
      securitySchemes: {
        SessionAuth: {
          type: 'apiKey',
          in: 'cookie',
          name: 'gameplan.sid',
          description: 'Session-based authentication using cookies'
        },
        AdminAuth: {
          type: 'apiKey',
          in: 'cookie',
          name: 'gameplan.sid',
          description: 'Admin role required (inherits SessionAuth)'
        },
        SuperAdminAuth: {
          type: 'apiKey',
          in: 'cookie',
          name: 'gameplan.sid',
          description: 'Super Admin role required (inherits SessionAuth)'
        }
      },
      responses: {
        UnauthorizedError: {
          description: 'Authentication required',
          content: {
            'text/html': {
              schema: {
                type: 'string',
                example: 'Redirected to /login'
              }
            }
          }
        },
        ForbiddenError: {
          description: 'Insufficient permissions',
          content: {
            'text/html': {
              schema: {
                type: 'string',
                example: 'Access denied. Admin privileges required.'
              }
            }
          }
        },
        NotFoundError: {
          description: 'Resource not found',
          content: {
            'text/html': {
              schema: {
                type: 'string',
                example: 'Resource not found'
              }
            }
          }
        },
        ValidationError: {
          description: 'Validation error',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  error: {
                    type: 'string',
                    example: 'Validation failed'
                  },
                  details: {
                    type: 'array',
                    items: {
                      type: 'object',
                      properties: {
                        field: { type: 'string' },
                        message: { type: 'string' }
                      }
                    }
                  }
                }
              }
            }
          }
        },
        RateLimitError: {
          description: 'Rate limit exceeded',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  error: {
                    type: 'string',
                    example: 'Too many requests from this IP, please try again later.'
                  },
                  retryAfter: {
                    type: 'number',
                    example: 900
                  }
                }
              }
            }
          }
        },
        ServerError: {
          description: 'Internal server error',
          content: {
            'text/html': {
              schema: {
                type: 'string',
                example: 'Internal server error'
              }
            }
          }
        }
      }
    },
    tags: [
      {
        name: 'Authentication',
        description: 'User authentication and profile management'
      },
      {
        name: 'Events',
        description: 'Gaming event management and participation'
      },
      {
        name: 'Games',
        description: 'Game database and search functionality'
      },
      {
        name: 'Search',
        description: 'Steam and RAWG game search APIs'
      },
      {
        name: 'Admin - Users',
        description: 'Administrative user management'
      },
      {
        name: 'Admin - Events',
        description: 'Administrative event management'
      },
      {
        name: 'Admin - Games',
        description: 'Administrative game management'
      },
      {
        name: 'Admin - System',
        description: 'System administration and monitoring'
      },
      {
        name: 'Admin - Cache',
        description: 'Cache management and monitoring'
      },
      {
        name: 'System',
        description: 'System health and configuration endpoints'
      }
    ]
  },
  apis: [
    './routes/*.js',
    './docs/schemas/*.js'
  ]
};

const specs = swaggerJsdoc(options);

// Custom CSS for better styling
const customCss = `
  .swagger-ui .topbar { display: none; }
  .swagger-ui .info .title { color: #2c3e50; }
  .swagger-ui .info .description { color: #34495e; }
  .swagger-ui .scheme-container { background: #ecf0f1; padding: 10px; border-radius: 5px; }
  .swagger-ui .opblock.opblock-post { border-color: #27ae60; }
  .swagger-ui .opblock.opblock-get { border-color: #3498db; }
  .swagger-ui .opblock.opblock-put { border-color: #f39c12; }
  .swagger-ui .opblock.opblock-delete { border-color: #e74c3c; }
`;

const swaggerUiOptions = {
  customCss,
  customSiteTitle: 'GamePlan API Documentation',
  customfavIcon: '/favicon.ico',
  swaggerOptions: {
    persistAuthorization: true,
    displayRequestDuration: true,
    filter: true,
    showExtensions: true,
    showCommonExtensions: true,
    docExpansion: 'none',
    defaultModelsExpandDepth: 2,
    defaultModelExpandDepth: 2
  }
};

module.exports = {
  specs,
  swaggerUi,
  swaggerUiOptions
};
