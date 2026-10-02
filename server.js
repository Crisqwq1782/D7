import express from 'express'
import cors from 'cors'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import pg from 'pg'
import dotenv from 'dotenv'

dotenv.config()

const app = express()
const { Pool } = pg
const PORT = Number(process.env.PORT || 3000)
const JWT_SECRET = process.env.JWT_SECRET || 'softjobs'

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/softjobs'
})

const logRequests = (req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`)
  next()
}

const validateLoginCredentials = (req, res, next) => {
  const { email, password } = req.body || {}

  if (!email || !password || !String(email).trim() || !String(password).trim()) {
    return res.status(400).json({ message: 'Email y password son obligatorios.' })
  }

  req.body = {
    ...req.body,
    email: String(email).trim(),
    password: String(password).trim()
  }

  next()
}

const validateUserCredentials = (req, res, next) => {
  const { email, password, rol, lenguage } = req.body || {}

  if (!email || !password || !rol || !lenguage || !String(email).trim() || !String(password).trim() || !String(rol).trim() || !String(lenguage).trim()) {
    return res.status(400).json({ message: 'Todos los campos son obligatorios.' })
  }

  req.body = {
    ...req.body,
    email: String(email).trim(),
    password: String(password).trim(),
    rol: String(rol).trim(),
    lenguage: String(lenguage).trim()
  }

  next()
}

const validateToken = (req, res, next) => {
  const authHeader = req.headers.authorization

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Token no proporcionado.' })
  }

  const token = authHeader.split(' ')[1]

  try {
    const decoded = jwt.verify(token, JWT_SECRET)
    req.user = decoded
    next()
  } catch (error) {
    console.error(error)
    return res.status(401).json({ message: 'Token inválido o expirado.' })
  }
}

app.use(cors())
app.use(express.json())
app.use(logRequests)

app.post('/usuarios', validateUserCredentials, async (req, res) => {
  const { email, password, rol, lenguage } = req.body

  try {
    const passwordHash = await bcrypt.hash(password, 10)
    const query = `
      INSERT INTO usuarios (email, password, rol, lenguage)
      VALUES ($1, $2, $3, $4)
      RETURNING id, email, rol, lenguage
    `
    const { rows } = await pool.query(query, [email, passwordHash, rol, lenguage])

    return res.status(201).json({
      message: 'Usuario registrado con éxito.',
      user: rows[0]
    })
  } catch (error) {
    console.error(error)

    if (error.code === '23505') {
      return res.status(409).json({ message: 'El email ya se encuentra registrado.' })
    }

    return res.status(500).json({ message: 'Error al registrar usuario.' })
  }
})

app.post('/login', validateLoginCredentials, async (req, res) => {
  const { email, password } = req.body

  try {
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email])
    const user = rows[0]

    if (!user) {
      return res.status(401).json({ message: 'Credenciales inválidas.' })
    }

    const validPassword = await bcrypt.compare(password, user.password)

    if (!validPassword) {
      return res.status(401).json({ message: 'Credenciales inválidas.' })
    }

    const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' })

    return res.json({ token })
  } catch (error) {
    console.error(error)
    return res.status(500).json({ message: 'Error al iniciar sesión.' })
  }
})

app.get('/usuarios', validateToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE email = $1', [req.user.email])
    const user = rows[0]

    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado.' })
    }

    const { password, ...userWithoutPassword } = user
    return res.json([userWithoutPassword])
  } catch (error) {
    console.error(error)
    return res.status(500).json({ message: 'Error al obtener usuario.' })
  }
})

app.use((error, req, res, next) => {
  console.error(error)
  return res.status(500).json({ message: 'Error interno del servidor.' })
})

app.listen(PORT, () => {
  console.log(`Servidor ejecutándose en http://localhost:${PORT}`)
})
