import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_antigravity_2026';
const JWT_EXPIRES_IN = '1h';

// ==========================================
// Middleware: CORS & JSON Body Parsing
// ==========================================
app.use(cors({
  origin: '*', // Allow all origins for dev / test
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Request logger for clear visibility
app.use((req, res, next) => {
  const time = new Date().toLocaleTimeString();
  console.log(`[${time}] ${req.method} ${req.url}`);
  next();
});

// ==========================================
// 1. In-Memory User Storage
// Structure: { id, username, password: hashedPassword, createdAt }
// ==========================================
const users = [];

// ==========================================
// 4. Authentication Middleware
// Verifies the Bearer JWT token from Authorization header
// ==========================================
export const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(401).json({
      success: false,
      message: 'Access denied. No authorization header provided.'
    });
  }

  // Expect header format: "Bearer <token>"
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return res.status(401).json({
      success: false,
      message: 'Malformed authorization header. Expected "Bearer <token>".'
    });
  }

  const token = parts[1];

  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(403).json({
          success: false,
          message: 'Token has expired. Please log in again.'
        });
      }
      return res.status(403).json({
        success: false,
        message: 'Invalid or corrupted token.'
      });
    }

    // Attach decoded token payload to request object
    req.user = decodedUser;
    next();
  });
};

// ==========================================
// API Routes
// ==========================================

// Health / Welcome Route
app.get('/', (req, res) => {
  res.json({
    status: 'online',
    message: 'Express In-Memory Authentication API is running smoothly.',
    registeredUsersCount: users.length,
    endpoints: [
      { method: 'POST', path: '/register', description: 'Register a new user' },
      { method: 'POST', path: '/login', description: 'Authenticate and receive JWT' },
      { method: 'GET', path: '/protected', description: 'Access guarded resource (requires Bearer token)' }
    ]
  });
});

// 2. /register (POST)
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validation: Check fields existence & types
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username and password are required fields.'
      });
    }

    const trimmedUsername = username.trim();
    if (trimmedUsername.length < 3) {
      return res.status(400).json({
        success: false,
        message: 'Username must be at least 3 characters long.'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters long.'
      });
    }

    // Check if user already exists (case-insensitive check)
    const existingUser = users.find(
      (u) => u.username.toLowerCase() === trimmedUsername.toLowerCase()
    );

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: `Username "${trimmedUsername}" is already taken.`
      });
    }

    // Securely hash password with bcrypt (10 salt rounds)
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user object and save to in-memory array
    const newUser = {
      id: `usr_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      username: trimmedUsername,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);

    console.log(`[AUTH] User registered: ${newUser.username} (ID: ${newUser.id})`);

    // Return success response without leaking password hash
    return res.status(201).json({
      success: true,
      message: `User '${newUser.username}' registered successfully!`,
      user: {
        id: newUser.id,
        username: newUser.username,
        createdAt: newUser.createdAt
      }
    });
  } catch (error) {
    console.error('[AUTH ERROR] Register failed:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error during registration.'
    });
  }
});

// 3. /login (POST)
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validation
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Please provide both username and password.'
      });
    }

    const trimmedUsername = username.trim();

    // Find user in in-memory array
    const user = users.find(
      (u) => u.username.toLowerCase() === trimmedUsername.toLowerCase()
    );

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid username or password.'
      });
    }

    // Verify password against hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid username or password.'
      });
    }

    // Sign JWT token
    const tokenPayload = {
      id: user.id,
      username: user.username
    };

    const token = jwt.sign(tokenPayload, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN
    });

    console.log(`[AUTH] User logged in: ${user.username}`);

    return res.status(200).json({
      success: true,
      message: 'Authentication successful!',
      token,
      tokenType: 'Bearer',
      expiresIn: JWT_EXPIRES_IN,
      user: {
        id: user.id,
        username: user.username
      }
    });
  } catch (error) {
    console.error('[AUTH ERROR] Login failed:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error during authentication.'
    });
  }
});

// 5. /protected (GET) - Guarded by authenticateToken
app.get('/protected', authenticateToken, (req, res) => {
  return res.status(200).json({
    success: true,
    message: 'Access granted! You have successfully reached the protected route.',
    user: req.user,
    timestamp: new Date().toISOString(),
    protectedData: {
      vaultStatus: 'UNLOCKED',
      securityClearance: 'Level-5 (Top Secret)',
      secretMessage: 'Quantum encryption key confirmed. Welcome to the restricted sector.',
      activeSessions: users.length,
      serverTime: new Date().toUTCString()
    }
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`===============================================`);
  console.log(` Authentication Server running on port ${PORT}`);
  console.log(` Local URL: http://localhost:${PORT}`);
  console.log(`===============================================`);
});

export default app;
