// routes/authRoutes.js

const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { verifyToken } = require('../middleware/middleware')
const { logger } = require('../logger')
// Route for user registration
router.post('/register', async (req, res) => {
  try {
    const checkUser = await User.findOne({ email: req.body.email });
    if (checkUser) {
      return res.status(404).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    // Create a new user
    const user = new User({
      first_name: req.body.first_name,
      last_name: req.body.last_name,
      email: req.body.email,
      password: hashedPassword,
    });

    // Save the user to the database
    const newUser = await user.save();

    res.status(201).json(newUser);
  } catch (error) {
    logger.error(error);
    res.status(500).json({ message: 'An error occurred while registering user.' });
  }
});

// Route for user login
router.post('/login', async (req, res) => {
  try {
    // Find the user by email
    const user = await User.findOne({ email: req.body.email });
    logger.info(req.body)
    if (!user) {
      return res.status(404).json({ message: 'Invalid credentials' });
    }

    // Compare passwords
    const isPasswordValid = await bcrypt.compare(req.body.password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({"token": token, "userdata": user });
  } catch (error) {
    logger.error(error);
    res.status(500).json({ message: 'An error occurred while logging in.' });
  }
});


// Route to get user ID
router.get('/user-id', verifyToken, async (req, res) => {
    try {
      
      const user = await User.findById(req.query.user_id);
       
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      res.status(200).json({ userId: user._id });
    } catch (error) {
      logger.error(error);
      res.status(500).json({ message: 'An error occurred while getting user ID' });
    }
  });
  
  // Route to check if user exists by email
  router.post('/check-user', async (req, res) => {
    try {
      const user = await User.findOne({ email: req.body.email });
  
      if (user) {
        return res.status(200).json({ exists: true });
      } else {
        return res.status(200).json({ exists: false });
      }
    } catch (error) {
      logger.error(error);
      res.status(500).json({ message: 'An error occurred while checking user existence' });
    }
  });
  
  // Route to reset user password
  router.post('/reset-password', async (req, res) => {
    try {
      const user = await User.findOne({ email: req.body.email });
  
      if (!user) {
        return res.status(404).json({ message: "User not found!! please check the email" });
      }
  
      const newPassword = req.body.password; // Generate or receive new password here
      const hashedPassword = await bcrypt.hash(newPassword, 10);
  
      user.password = hashedPassword;
      await user.save();
  
      return res.status(200).json({ message: `Password has been reset for ${user.email}` });
    } catch (error) {
      logger.error(error);
      res.status(500).json({ message: 'An error occurred while resetting password' });
    }
  });


// Route to validate JWT token
router.post('/validate-user',verifyToken, (req, res) => {
    const token = req.body.token;
  
    if (!token) {
      return res.status(400).json({ message: 'Token is required' });
    }
  
    try {
      jwt.verify(token, process.env.JWT_SECRET);
      res.status(200).json({ isValid: true });
    } catch (error) {
      logger.error(error);
      res.status(401).json({ isValid: false });
    }
  });
  

module.exports = router;


/**
 * @swagger
 * tags:
 *   name: Authentication
 *   description: User authentication APIs
 */

/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               first_name:
 *                 type: string
 *               last_name:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '201':
 *         description: User registered successfully
 *       '500':
 *         description: Internal server error
 */

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Log in with existing user credentials
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '200':
 *         description: User logged in successfully
 *       '401':
 *         description: Invalid credentials
 *       '500':
 *         description: Internal server error
 */
/**
 * @swagger
 * /auth/user-id:
 *   get:
 *     summary: Get user ID
 *     description: Retrieve the user ID of the authenticated user.
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: User ID retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 userId:
 *                   type: string
 *       '401':
 *         description: Unauthorized request
 *       '404':
 *         description: User not found
 *       '500':
 *         description: Internal server error
 */

/**
 * @swagger
 * /auth/check-user:
 *   post:
 *     summary: Check if user exists
 *     description: Check if a user exists by their email address.
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *     responses:
 *       '200':
 *         description: User existence checked successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 exists:
 *                   type: boolean
 *       '500':
 *         description: Internal server error
 */

/**
 * @swagger
 * /auth/reset-password:
 *   post:
 *     summary: Reset user password
 *     description: Reset the password for a user by their email address.
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *     responses:
 *       '200':
 *         description: User password reset successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 password_reset:
 *                   type: boolean
 *       '500':
 *         description: Internal server error
 */
/**
 * @swagger
 * /auth/validate-user:
 *   post:
 *     summary: Validate JWT token
 *     description: Validate the provided JWT token to check its authenticity.
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               token:
 *                 type: string
 *                 description: JWT token to validate
 *     responses:
 *       '200':
 *         description: Token is valid
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 isValid:
 *                   type: boolean
 *                   description: Indicates whether the token is valid or not
 *       '400':
 *         description: Bad request, token is required
 *       '401':
 *         description: Unauthorized, token is invalid
 *       '500':
 *         description: Internal server error
 */

