const { body } = require('express-validator');
const { checkXSS, validateFutureDate } = require('../middleware/validation');

/**
 * Validation rules for event creation
 */
const validateEventCreation = [
  // Event name validation
  body('name')
    .trim()
    .isLength({ min: 3, max: 200 })
    .withMessage('Event name must be between 3 and 200 characters')
    .matches(/^[a-zA-Z0-9\s\-_:!?.,()&]+$/)
    .withMessage('Event name contains invalid characters')
    .custom(checkXSS)
    .withMessage('Event name contains potentially dangerous content')
    .escape(),

  // Event description validation
  body('description')
    .trim()
    .isLength({ min: 10, max: 2000 })
    .withMessage('Event description must be between 10 and 2000 characters')
    .custom(checkXSS)
    .withMessage('Event description contains potentially dangerous content')
    .escape(),

  // Player limit validation
  body('playerLimit')
    .isInt({ min: 1, max: 100 })
    .withMessage('Player limit must be between 1 and 100')
    .toInt(),

  // Date validation
  body('date')
    .isISO8601()
    .withMessage('Invalid date format')
    .custom(validateFutureDate)
    .withMessage('Event date must be in the future')
    .toDate(),

  // Platforms validation
  body('platforms')
    .optional()
    .custom((value) => {
      const allowedPlatforms = ['PC', 'PlayStation', 'Xbox', 'Nintendo Switch'];
      
      if (!value) return true; // Optional field
      
      // Handle both array and single string
      const platforms = Array.isArray(value) ? value : [value];
      
      for (const platform of platforms) {
        if (!allowedPlatforms.includes(platform)) {
          throw new Error(`Invalid platform: ${platform}`);
        }
      }
      
      if (platforms.length === 0) {
        throw new Error('At least one platform must be selected');
      }
      
      if (platforms.length > allowedPlatforms.length) {
        throw new Error('Too many platforms selected');
      }
      
      return true;
    }),

  // Game selection validation
  body('gameSelection')
    .notEmpty()
    .withMessage('Game selection is required')
    .isJSON()
    .withMessage('Invalid game selection format')
    .custom((value) => {
      try {
        const gameData = JSON.parse(value);
        
        if (!gameData.type) {
          throw new Error('Game selection type is required');
        }
        
        const allowedTypes = ['existing', 'steam', 'rawg', 'manual'];
        if (!allowedTypes.includes(gameData.type)) {
          throw new Error('Invalid game selection type');
        }
        
        // Validate based on type
        switch (gameData.type) {
          case 'existing':
            if (!gameData.gameId || typeof gameData.gameId !== 'string') {
              throw new Error('Valid game ID is required for existing games');
            }
            break;
            
          case 'steam':
            if (!gameData.data || !gameData.data.appid || !gameData.data.name) {
              throw new Error('Valid Steam game data is required');
            }
            break;
            
          case 'rawg':
            if (!gameData.data || !gameData.data.id || !gameData.data.name) {
              throw new Error('Valid RAWG game data is required');
            }
            break;
            
          case 'manual':
            if (!gameData.data || !gameData.data.name) {
              throw new Error('Game name is required for manual games');
            }
            if (gameData.data.name.length < 2 || gameData.data.name.length > 200) {
              throw new Error('Game name must be between 2 and 200 characters');
            }
            break;
        }
        
        return true;
      } catch (parseError) {
        throw new Error('Invalid game selection data');
      }
    }),

  // Extensions validation (optional)
  body('extensions')
    .optional({ checkFalsy: true })
    .custom((value) => {
      if (!value || value.trim() === '' || value.trim() === '[]') {
        return true; // Empty extensions are allowed
      }
      
      try {
        let extensionData;
        
        if (Array.isArray(value)) {
          const lastEntry = value[value.length - 1];
          if (lastEntry && lastEntry.trim() !== '[]') {
            extensionData = JSON.parse(lastEntry);
          } else {
            return true; // Empty array
          }
        } else {
          extensionData = JSON.parse(value);
        }
        
        if (!Array.isArray(extensionData)) {
          throw new Error('Extensions must be an array');
        }
        
        if (extensionData.length > 10) {
          throw new Error('Too many extensions (maximum 10 allowed)');
        }
        
        for (const ext of extensionData) {
          if (!ext.name || !ext.downloadLink || !ext.installationTime) {
            throw new Error('Each extension must have name, downloadLink, and installationTime');
          }
          
          if (typeof ext.name !== 'string' || ext.name.length > 100) {
            throw new Error('Extension name must be a string with maximum 100 characters');
          }
          
          if (typeof ext.downloadLink !== 'string' || ext.downloadLink.length > 500) {
            throw new Error('Extension download link must be a string with maximum 500 characters');
          }
          
          if (typeof ext.installationTime !== 'string' || ext.installationTime.length > 200) {
            throw new Error('Extension installation time must be a string with maximum 200 characters');
          }
          
          // Basic URL validation for download link
          try {
            new URL(ext.downloadLink);
          } catch {
            throw new Error('Extension download link must be a valid URL');
          }
          
          // Check for XSS in extension fields
          checkXSS(ext.name);
          checkXSS(ext.downloadLink);
          checkXSS(ext.installationTime);
        }
        
        return true;
      } catch (parseError) {
        throw new Error('Invalid extensions format');
      }
    })
];

/**
 * Validation rules for event editing
 */
const validateEventEdit = [
  // Event name validation
  body('name')
    .trim()
    .isLength({ min: 3, max: 200 })
    .withMessage('Event name must be between 3 and 200 characters')
    .matches(/^[a-zA-Z0-9\s\-_:!?.,()&]+$/)
    .withMessage('Event name contains invalid characters')
    .custom(checkXSS)
    .withMessage('Event name contains potentially dangerous content')
    .escape(),

  // Game ID validation
  body('gameId')
    .notEmpty()
    .withMessage('Game ID is required')
    .isMongoId()
    .withMessage('Invalid game ID format'),

  // Event description validation
  body('description')
    .trim()
    .isLength({ min: 10, max: 2000 })
    .withMessage('Event description must be between 10 and 2000 characters')
    .custom(checkXSS)
    .withMessage('Event description contains potentially dangerous content')
    .escape(),

  // Player limit validation
  body('playerLimit')
    .isInt({ min: 1, max: 100 })
    .withMessage('Player limit must be between 1 and 100')
    .toInt(),

  // Date validation
  body('date')
    .isISO8601()
    .withMessage('Invalid date format')
    .custom(validateFutureDate)
    .withMessage('Event date must be in the future')
    .toDate(),

  // Platforms validation
  body('platforms')
    .optional()
    .custom((value) => {
      const allowedPlatforms = ['PC', 'PlayStation', 'Xbox', 'Nintendo Switch'];
      
      if (!value) return true; // Optional field
      
      // Handle both array and single string
      const platforms = Array.isArray(value) ? value : [value];
      
      for (const platform of platforms) {
        if (!allowedPlatforms.includes(platform)) {
          throw new Error(`Invalid platform: ${platform}`);
        }
      }
      
      if (platforms.length === 0) {
        throw new Error('At least one platform must be selected');
      }
      
      return true;
    }),

  // Extensions validation (same as creation)
  body('extensions')
    .optional({ checkFalsy: true })
    .custom((value) => {
      if (!value || value.trim() === '' || value.trim() === '[]') {
        return true; // Empty extensions are allowed
      }
      
      try {
        let extensionData;
        
        if (Array.isArray(value)) {
          const lastEntry = value[value.length - 1];
          if (lastEntry && lastEntry.trim() !== '[]') {
            extensionData = JSON.parse(lastEntry);
          } else {
            return true; // Empty array
          }
        } else {
          extensionData = JSON.parse(value);
        }
        
        if (!Array.isArray(extensionData)) {
          throw new Error('Extensions must be an array');
        }
        
        if (extensionData.length > 10) {
          throw new Error('Too many extensions (maximum 10 allowed)');
        }
        
        for (const ext of extensionData) {
          if (!ext.name || !ext.downloadLink || !ext.installationTime) {
            throw new Error('Each extension must have name, downloadLink, and installationTime');
          }
          
          if (typeof ext.name !== 'string' || ext.name.length > 100) {
            throw new Error('Extension name must be a string with maximum 100 characters');
          }
          
          if (typeof ext.downloadLink !== 'string' || ext.downloadLink.length > 500) {
            throw new Error('Extension download link must be a string with maximum 500 characters');
          }
          
          if (typeof ext.installationTime !== 'string' || ext.installationTime.length > 200) {
            throw new Error('Extension installation time must be a string with maximum 200 characters');
          }
          
          // Basic URL validation for download link
          try {
            new URL(ext.downloadLink);
          } catch {
            throw new Error('Extension download link must be a valid URL');
          }
          
          // Check for XSS in extension fields
          checkXSS(ext.name);
          checkXSS(ext.downloadLink);
          checkXSS(ext.installationTime);
        }
        
        return true;
      } catch (parseError) {
        throw new Error('Invalid extensions format');
      }
    })
];

/**
 * Validation rules for event duplication
 */
const validateEventDuplication = [
  // Event name validation (optional, will use original if not provided)
  body('name')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ min: 3, max: 200 })
    .withMessage('Event name must be between 3 and 200 characters')
    .matches(/^[a-zA-Z0-9\s\-_:!?.,()&]+$/)
    .withMessage('Event name contains invalid characters')
    .custom(checkXSS)
    .withMessage('Event name contains potentially dangerous content')
    .escape(),

  // Event description validation (optional)
  body('description')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 2000 })
    .withMessage('Event description cannot exceed 2000 characters')
    .custom(checkXSS)
    .withMessage('Event description contains potentially dangerous content')
    .escape(),

  // Player limit validation (optional)
  body('playerLimit')
    .optional({ checkFalsy: true })
    .isInt({ min: 1, max: 100 })
    .withMessage('Player limit must be between 1 and 100')
    .toInt(),

  // Date validation (required for duplication)
  body('date')
    .notEmpty()
    .withMessage('Event date is required')
    .isISO8601()
    .withMessage('Invalid date format')
    .custom(validateFutureDate)
    .withMessage('Event date must be in the future')
    .toDate(),

  // Platforms validation
  body('platforms')
    .notEmpty()
    .withMessage('At least one platform must be selected')
    .custom((value) => {
      const allowedPlatforms = ['PC', 'PlayStation', 'Xbox', 'Nintendo Switch'];
      
      // Handle both array and single string
      const platforms = Array.isArray(value) ? value : [value];
      
      for (const platform of platforms) {
        if (!allowedPlatforms.includes(platform)) {
          throw new Error(`Invalid platform: ${platform}`);
        }
      }
      
      if (platforms.length === 0) {
        throw new Error('At least one platform must be selected');
      }
      
      return true;
    })
];

module.exports = {
  validateEventCreation,
  validateEventEdit,
  validateEventDuplication
};
