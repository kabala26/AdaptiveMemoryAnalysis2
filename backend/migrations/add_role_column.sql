-- Add role column to users table
-- Migration to add role-based access control

ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(32) NOT NULL DEFAULT 'analyst';

-- Add comment for documentation
COMMENT ON COLUMN users.role IS 'User role: admin or analyst';
