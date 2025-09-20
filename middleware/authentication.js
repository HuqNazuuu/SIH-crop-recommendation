// dont let unauthenticated user to visit authenticated place
import jwt from 'jsonwebtoken'

const auth = async (req, next) => {
  // check header
  const token = req.cookies.token

  if (!token) {
    throw new Error('Authentication invalid')
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET)
    req.user = { userId: payload.userId }
    next()
  } catch (error) {
    throw new Error('Authentication invalid')
  }
}

export default auth
