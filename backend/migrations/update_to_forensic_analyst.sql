-- Rename analyst role to forensic_analyst
-- Run this once against the production PostgreSQL database.

UPDATE users SET role = 'forensic_analyst' WHERE role = 'analyst';
UPDATE users SET role = 'forensic_analyst' WHERE role = 'security_researcher';

ALTER TABLE users ALTER COLUMN role SET DEFAULT 'forensic_analyst';

COMMENT ON COLUMN users.role IS 'User role: admin or forensic_analyst';
