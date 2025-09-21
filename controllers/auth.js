import User from '../models/user.js'
import { StatusCodes } from 'http-status-codes'
import { BadRequestError, UnauthenticatedError } from '../errors/index.js'
import jwt from 'jsonwebtoken'
import { OAuth2Client } from 'google-auth-library'
import bcrypt from 'bcryptjs'
import UserOtpVerification from '../models/userOtp.js'
import { transporter } from '../components/transporter.js'
import nodemailer from 'nodemailer'
import { hashPassword } from '../components/hashPassword.js'

const register = async (req, res) => {
  const user = await User.create({ ...req.body })

  const jwtToken = user.createJWT()

  res.cookie('token', jwtToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Lax',
    maxAge: 24 * 60 * 60 * 1000, // 1 day
  })

  await sendOtp(user, res)

  // console.log('Token:', token)
  // send response
  res.status(StatusCodes.OK).json({
    user: {
      name: user.name,
      email: user.email,
      userName: user.userName,
      verified: user.verified,
      status: user.status,
      joinedAt: user.joinedAt,
    },
  })
}

const login = async (req, res) => {
  const { email, password } = req.body

  if (!email || !password) {
    throw new BadRequestError('Please provide email and password')
  }
  const user = await User.findOne({ email })
  if (!user) {
    throw new UnauthenticatedError('Invalid User')
  }
  console.log(password)
  const isPasswordCorrect = await user.comparePassword(password)
  if (!isPasswordCorrect) {
    throw new UnauthenticatedError('Invalid Password')
  }
  // compare password
  const jwtToken = user.createJWT()
  // creating cookie
  res.cookie('token', jwtToken, {
    httpOnly: true,
    sameSite: 'Lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000,
  })
  await sendOtp(user, res)
  // send response
  res.status(StatusCodes.OK).json({
    user: {
      name: user.name,
      email: user.email,
      status: user.status,
      verified: user.verified,
      userName: user.userName,
    },
  })
}
const logout = async (req, res) => {
  try {
    const token = req.cookies.token
    if (!token) {
      return res
        .status(StatusCodes.UNAUTHORIZED)
        .json({ message: 'No token found' })
    }

    // decode token
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    const email = decoded.email
    // clear cookie
    res.clearCookie('token', {
      httpOnly: true,
      sameSite: 'Lax',
      secure: process.env.NODE_ENV === 'production',
    })
    await User.updateOne({ email }, { verified: 'Pending' })
    // send response
    res.status(StatusCodes.OK).json({ message: 'Logged out successfully' })
  } catch (error) {
    throw new Error(error.message)
  }
}

const googleLogin = async (req, res) => {
  const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID)
  const { token } = req.body
  if (!token) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ message: 'Token is required' })
  }
  // verifying the token
  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    })

    const payload = ticket.getPayload()

    let user = await User.findOne({ email: payload.email })

    if (!user) {
      user = await User.create({
        name: payload.name,
        email: payload.email,
        picture: payload.picture,
        sub: payload.sub,
      })
    }
    const jwtPayload = { userId: user._id }

    const jwtToken = jwt.sign(jwtPayload, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_LIFETIME,
    })

    res.cookie('token', jwtToken, {
      httpOnly: true,
      sameSite: 'Lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000,
    })

    sendWelcomeEmail(user.email, user.name)
    //await sendOtp(user, res)
    res.status(StatusCodes.OK).json({
      user: {
        name: user.name,
        email: user.email,
        imageUrl: user.picture,
        //verified: user.verified,
      },
    })
  } catch (error) {
    console.error(error)
    res.status(401).json({ error: 'Invalid Google token' })
  }
}
const checkAuth = async (req, res) => {
  //check if the user is authenticated or not ,if authenticated send user info
  //  const token = req.cookies.token

  try {
    /*
    if (!token) {
      return res
        .status(StatusCodes.UNAUTHORIZED)
        .json({ message: 'Unauthorized' })
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    if (!decoded) {
      return res
        .status(StatusCodes.UNAUTHORIZED)
        .json({ message: 'Unauthorized' })
    }*/
    const user = await User.findById(decoded.userId)
    if (!user) {
      return res
        .status(StatusCodes.NOT_FOUND)
        .json({ message: 'User not found' })
    }

    return res.status(StatusCodes.OK).json({
      user: {
        name: user.name,
        email: user.email,
        imageUrl: user.picture || null,
        joinedAt: user.joinedAt,
        userName: user.userName,
        status: user.status,
        decoded,
      },
    })
  } catch (error) {
    console.error(error)
    return res
      .status(StatusCodes.UNAUTHORIZED)
      .json({ message: 'Unauthorized' })
  }
}

const getAllUsers = async (req, res) => {
  try {
    let { search } = req.query || ''
    search = String(search)

    const query = {
      $or: [
        //using an array inside a or operator for multiple search conditions.

        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { userName: { $regex: search, $options: 'i' } },
      ],
    }
    const page = parseInt(req.query.page) || 1
    const limit = parseInt(req.query.limit) || 6
    const skip = (page - 1) * limit

    const users = await User.find(query)
      .select('-password')
      .skip(skip)
      .limit(limit)
    const total = await User.countDocuments()
    const pages = Math.ceil(total / limit)
    res.status(StatusCodes.OK).json({ users, total, page, pages })
  } catch (error) {
    console.error(error)
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      message: 'Error fetching users',
    })
  }
}
const sendOtp = async ({ _id, email }, res) => {
  try {
    const otp = `${Math.floor(1000 + Math.random() * 9000)}`

    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: 'Verify Your Email',
      html: `<p>Enter <b>${otp}</b> in the web app to verify your email address .</p><p>This code <b>expires in 1 hour</b>.</p>`,
    }

    const saltRounds = 10

    const hashedOTP = await bcrypt.hash(otp, saltRounds)
    await UserOtpVerification.create({
      userId: _id,
      otp: hashedOTP,
      createdAt: Date.now(),
      expiresAt: Date.now() + 300000,
    })

    transporter.sendMail(mailOptions)
  } catch (error) {
    res.json({ status: 'FAILED', message: error.message })
  }
}

const verifyOTP = async (req, res) => {
  try {
    const { userId, otp } = req.body

    if (!userId || !otp) {
      throw new Error('OTP are empty.Please, enter otp .')
    }
    const UserOTPRecords = await UserOtpVerification.find({
      userId,
    })

    if (UserOTPRecords.length <= 0) {
      throw new Error('Account record does not exist or verified already.')
    }
    const { expiresAt } = UserOTPRecords[0]
    const hashedOTP = UserOTPRecords[0].otp

    if (expiresAt < Date.now()) {
      await UserOtpVerification.deleteMany({ userId })
      throw new Error('Code has expired. PLease request again.')
    }
    const validOTP = await hashPassword(otp, hashedOTP)

    if (!validOTP) {
      throw new Error('Invalid code passed.Please, check your email.')
    }

    await User.updateOne({ _id: userId, verified: 'Verified' })

    await UserOtpVerification.deleteMany({ userId })

    const user = await User.findById(userId)
    sendWelcomeEmail(user.email, user.name)
    console.log(user.name, user.email)
    res.json({
      status: 'VERIFIED',
      message: 'User email verified succesfully.',
      name: user.name,
      email: user.email,
    })
  } catch (error) {
    res.json({ status: 'FAILED', message: error.message })
  }
}

const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body

    if (!email) {
      return res.status(400).send({ message: 'Please provide email' })
    }

    const checkUser = await User.findOne({ email })

    if (!checkUser) {
      return res
        .status(400)
        .send({ message: 'User not found. Please register.' })
    }

    const token = jwt.sign({ email }, process.env.JWT_SECRET, {
      expiresIn: '10h',
    })

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      secure: true,
      auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
      },
    })

    const receiver = {
      from: process.env.EMAIL,
      to: email,
      subject: 'Password Reset Request',
      text: `Click on this link to generate your new password ${process.env.AUTH_URL}/reset-password/${token} `,
    }

    await transporter.sendMail(receiver)
    return res.status(200).send({
      message: 'Password reset link send succesfully on your gmail account.',
    })
  } catch (error) {
    return res.status(500).send({ message: error.message })
  }
}
const resetPassword = async (req, res) => {
  try {
    const { token } = req.params
    const { password } = req.body

    if (!password) {
      return res.status(400).send({ message: 'Please provide password' })
    }
    const decode = jwt.verify(token, process.env.JWT_SECRET)
    const user = await User.findOne({ email: decode.email })

    //const newPassword = await hashPassword(password)   //pre is already hashing it,using it will be hasing twice.which will not match will comparing the password

    user.password = password
    await user.save()

    return res.status(200).send({ message: 'Password reset succesfully.' })
  } catch (error) {
    return res.status(500).send({ message: error.message })
  }
}

export const sendWelcomeEmail = async (userEmail, userName) => {
  try {
    const mailOptions = {
      from: process.env.EMAIL,
      to: userEmail,
      subject: 'Welcome !',
      html: `
        <h2>Welcome, ${userName}!</h2>
        <p>Thank you for connecting with us. We are excited to have you on board.</p>
        <p>Start exploring and enjoy our services!</p>
      `,
    }

    await transporter.sendMail(mailOptions)
  } catch (error) {
    console.error('Error sending welcome email:', error.message)
  }
}

export {
  register,
  login,
  logout,
  googleLogin,
  checkAuth,
  getAllUsers,
  verifyOTP,
  forgotPassword,
  resetPassword,
}

//https://github.com/HuqNazuuu/SIH-crop-recommendation
