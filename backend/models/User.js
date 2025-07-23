const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto-js');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  apiKeys: {
    openai: { type: String, default: '' },
    claude: { type: String, default: '' },
    gemini: { type: String, default: '' },
    grok: { type: String, default: '' }
  },
  preferredProvider: { type: String, default: 'openai' },
  createdAt: { type: Date, default: Date.now }
});

// Encrypt API keys before saving
userSchema.pre('save', function(next) {
  const encryptionKey = process.env.ENCRYPTION_KEY;
  
  // Only encrypt if keys have been modified
  if (this.isModified('apiKeys.openai') && this.apiKeys.openai) {
    this.apiKeys.openai = crypto.AES.encrypt(this.apiKeys.openai, encryptionKey).toString();
  }
  
  if (this.isModified('apiKeys.claude') && this.apiKeys.claude) {
    this.apiKeys.claude = crypto.AES.encrypt(this.apiKeys.claude, encryptionKey).toString();
  }
  
  if (this.isModified('apiKeys.gemini') && this.apiKeys.gemini) {
    this.apiKeys.gemini = crypto.AES.encrypt(this.apiKeys.gemini, encryptionKey).toString();
  }
  
  if (this.isModified('apiKeys.grok') && this.apiKeys.grok) {
    this.apiKeys.grok = crypto.AES.encrypt(this.apiKeys.grok, encryptionKey).toString();
  }
  
  next();
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  // Only hash the password if it has been modified or is new
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to check if password is correct
userSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Method to decrypt API key
userSchema.methods.getDecryptedApiKey = function(provider) {
  if (!this.apiKeys[provider]) return '';
  
  const encryptionKey = process.env.ENCRYPTION_KEY;
  const bytes = crypto.AES.decrypt(this.apiKeys[provider], encryptionKey);
  return bytes.toString(crypto.enc.Utf8);
};

module.exports = mongoose.model('User', userSchema);
