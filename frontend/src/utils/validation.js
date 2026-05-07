export function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return re.test(String(email).toLowerCase())
}

export function validatePassword(password) {
  if (password.length < 8) return 'Password must be at least 8 characters'
  if (!/[A-Z]/.test(password)) return 'Include at least one uppercase letter'
  if (!/[0-9]/.test(password)) return 'Include at least one number'
  return null
}

export function validateLoginForm({ email, password }) {
  const errors = {}
  if (!email)               errors.email    = 'Email is required'
  else if (!validateEmail(email)) errors.email = 'Enter a valid email address'
  if (!password)            errors.password = 'Password is required'
  return errors
}

export function validateRegisterForm({ email, password, name }) {
  const errors = {}
  if (!name || name.trim().length < 2) errors.name = 'Full name must be at least 2 characters'
  if (!email)                   errors.email    = 'Email is required'
  else if (!validateEmail(email)) errors.email  = 'Enter a valid email address'
  const pwErr = validatePassword(password)
  if (!password) errors.password = 'Password is required'
  else if (pwErr) errors.password = pwErr
  return errors
}
