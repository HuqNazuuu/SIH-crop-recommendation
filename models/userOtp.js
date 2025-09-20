import mongoose from 'mongoose'

const OtpSchema = new mongoose.Schema({
  userId: String,
  otp: String,
  createdAt: Date,
  expiresAt: Date,
})

const UserOtpVerification = mongoose.model('UserOTPVerification', OtpSchema)

export default UserOtpVerification
