import mongoose from 'mongoose'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please provide name'],
    maxlength: 50,
    minlength: 3,
  },
  email: {
    type: String,
    required: [true, 'Please provide email'],
    match: [
      /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
      'Please provide a valid email',
    ],
    unique: true,
  },
  password: {
    type: String,
    validate: {
      validator: function (value) {
        return this.provider === 'google' || (value && value.length > 0)
      },
      message: 'Password is required for local signups.',
    },
  },
  provider: {
    type: String,
    enum: ['local', 'google'],
    default: 'local',
  },
  userName: {
    type: String,
    unique: true,
  },
  imageUrl: {
    type: String,
  },
  joinedAt: {
    type: Date,
    default: Date.now(),
  },
  verified: {
    type: String,
    enum: ['Pending', 'Verified'],
    default: 'Pending',
  },
  status: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user',
  },
})

UserSchema.pre('save', async function () {
  if (!this.isModified('password') || !this.password) return
  const salt = await bcrypt.genSalt(10)
  this.password = await bcrypt.hash(this.password, salt)
})

UserSchema.methods.createJWT = function () {
  return jwt.sign(
    { userId: this._id, name: this.name, email: this.email },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_LIFETIME,
    }
  )
}

UserSchema.methods.comparePassword = async function (candidatePassword) {
  console.log('Login password:', candidatePassword)
  console.log('Stored hash:', this.password)
  const isMatch = await bcrypt.compare(candidatePassword, this.password)
  console.log('Password match:', isMatch)
  return isMatch
}

const User = mongoose.model('User', UserSchema)

export default User
