
import { getUserByUsername } from "../../db/users.js"
import bcrypt from "bcrypt"
export default defineEventHandler(async (event) => {
  const body = await readBody(event)

  const { username, password } = body

  if (!username || !password) {
    return sendError(event, createError({
      statusCode: 400,
      statusMessage: 'Ivalid params'
    }))
  }

  const user = await getUserByUsername(username)

  if (!user) {
    return sendError(event, createError({
      statusCode: 400,
      statusMessage: 'Username or password is invalid'
    }))
  }

  const doesThePasswordMatch = await bcrypt.compare(password, user.password)

  const {accessToken, refreshToken} = generateTokens

  return {
    user: user,
    doesThePasswordMatch
  }
})