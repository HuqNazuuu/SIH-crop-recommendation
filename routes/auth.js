import express from 'express'
import {
  register,
  login,
  logout,
  checkAuth,
  getAllUsers,
  verifyOTP,
  forgotPassword,
  resetPassword,
} from '../controllers/auth.js'
import { googleLogin } from '../controllers/auth.js'
const router = express.Router()

router.post('/register', register)
router.post('/login', login)
router.get('/logout', logout)
router.post('/google-login', googleLogin)
router.get('/check-auth', checkAuth)
router.get('/get-all-users', getAllUsers)
router.post('/verifyOTP', verifyOTP)
router.post('/forget-password', forgotPassword)
router.post('/reset-password/:token', resetPassword)

export default router
