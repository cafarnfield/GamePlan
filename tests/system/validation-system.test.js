/**
 * Test script to verify the GamePlan validation system
 * Run with: node test-validation-system.js
 */

const {
  userSchemas,
  eventSchemas,
  gameSchemas,
  adminSchemas,
  commonSchemas
} = require('./validators');

console.log('🧪 Testing GamePlan Validation System...\n');

// Test 1: User Registration Schema
console.log('1. Testing User Registration Schema');
const userRegistrationTest = {
  name: 'John Doe',
  email: 'john.doe@example.com',
  password: 'SecurePass123!',
  confirmPassword: 'SecurePass123!',
  gameNickname: 'JohnGamer'
};

const { error: userError, value: userValue } = userSchemas.userRegistrationSchema.validate(userRegistrationTest);
if (userError) {
  console.log('❌ User registration validation failed:', userError.details[0].message);
} else {
  console.log('✅ User registration validation passed');
  console.log('   Sanitized data:', JSON.stringify(userValue, null, 2));
}

// Test 2: Event Creation Schema
console.log('\n2. Testing Event Creation Schema');
const eventCreationTest = {
  name: 'Epic Gaming Session',
  description: 'Join us for an amazing gaming experience with friends and fellow gamers!',
  playerLimit: 8,
  date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // One week from now
  platforms: ['PC', 'PlayStation'],
  gameSelection: {
    type: 'existing',
    gameId: '507f1f77bcf86cd799439011' // Valid MongoDB ObjectId
  },
  extensions: []
};

const { error: eventError, value: eventValue } = eventSchemas.eventCreationSchema.validate(eventCreationTest);
if (eventError) {
  console.log('❌ Event creation validation failed:', eventError.details[0].message);
} else {
  console.log('✅ Event creation validation passed');
  console.log('   Event name:', eventValue.name);
  console.log('   Player limit:', eventValue.playerLimit);
  console.log('   Platforms:', eventValue.platforms);
}

// Test 3: Game Addition Schema
console.log('\n3. Testing Game Addition Schema');
const gameAdditionTest = {
  name: 'Awesome Game 2024',
  description: 'An incredible gaming experience',
  imageUrl: 'https://example.com/game-image.jpg',
  steamAppId: 123456
};

const { error: gameError, value: gameValue } = gameSchemas.manualGameAdditionSchema.validate(gameAdditionTest);
if (gameError) {
  console.log('❌ Game addition validation failed:', gameError.details[0].message);
} else {
  console.log('✅ Game addition validation passed');
  console.log('   Game name:', gameValue.name);
  console.log('   Source:', gameValue.source);
}

// Test 4: Admin System Operation Schema
console.log('\n4. Testing Admin System Operation Schema');
const adminOperationTest = {
  operation: 'backup',
  confirm: true,
  notes: 'Regular scheduled backup',
  parameters: {
    dryRun: false,
    backupLocation: '/backups/gameplan'
  }
};

const { error: adminError, value: adminValue } = adminSchemas.systemOperationSchema.validate(adminOperationTest);
if (adminError) {
  console.log('❌ Admin operation validation failed:', adminError.details[0].message);
} else {
  console.log('✅ Admin operation validation passed');
  console.log('   Operation:', adminValue.operation);
  console.log('   Confirmed:', adminValue.confirm);
}

// Test 5: Common Schema - MongoDB ObjectId
console.log('\n5. Testing MongoDB ObjectId Validation');
const validObjectId = '507f1f77bcf86cd799439011';
const invalidObjectId = 'invalid-id';

const { error: validIdError } = commonSchemas.mongoId.validate(validObjectId);
const { error: invalidIdError } = commonSchemas.mongoId.validate(invalidObjectId);

if (!validIdError) {
  console.log('✅ Valid ObjectId validation passed');
} else {
  console.log('❌ Valid ObjectId validation failed');
}

if (invalidIdError) {
  console.log('✅ Invalid ObjectId correctly rejected');
} else {
  console.log('❌ Invalid ObjectId incorrectly accepted');
}

// Test 6: Email Validation
console.log('\n6. Testing Email Validation');
const validEmail = 'user@example.com';
const invalidEmail = 'not-an-email';

const { error: validEmailError, value: emailValue } = commonSchemas.email.validate(validEmail);
const { error: invalidEmailError } = commonSchemas.email.validate(invalidEmail);

if (!validEmailError) {
  console.log('✅ Valid email validation passed');
  console.log('   Normalized email:', emailValue);
} else {
  console.log('❌ Valid email validation failed');
}

if (invalidEmailError) {
  console.log('✅ Invalid email correctly rejected:', invalidEmailError.details[0].message);
} else {
  console.log('❌ Invalid email incorrectly accepted');
}

// Test 7: Password Strength Validation
console.log('\n7. Testing Password Strength Validation');
const strongPassword = 'SecurePass123!';
const weakPassword = '123';

const { error: strongPassError } = commonSchemas.password.validate(strongPassword);
const { error: weakPassError } = commonSchemas.password.validate(weakPassword);

if (!strongPassError) {
  console.log('✅ Strong password validation passed');
} else {
  console.log('❌ Strong password validation failed');
}

if (weakPassError) {
  console.log('✅ Weak password correctly rejected:', weakPassError.details[0].message);
} else {
  console.log('❌ Weak password incorrectly accepted');
}

// Test 8: Error Handling Test
console.log('\n8. Testing Error Handling');
const invalidUserData = {
  name: 'A', // Too short
  email: 'invalid-email',
  password: '123', // Too weak
  confirmPassword: '456' // Doesn't match
};

const { error: multiError } = userSchemas.userRegistrationSchema.validate(invalidUserData, {
  abortEarly: false // Get all errors
});

if (multiError) {
  console.log('✅ Multiple validation errors correctly detected:');
  multiError.details.forEach((detail, index) => {
    console.log(`   ${index + 1}. ${detail.path.join('.')}: ${detail.message}`);
  });
} else {
  console.log('❌ Multiple validation errors not detected');
}

console.log('\n🎉 Validation system testing completed!');
console.log('\n📚 For more information, see VALIDATION_SYSTEM.md');
