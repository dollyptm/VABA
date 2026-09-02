-- Enhanced User Profile Schema
-- Additional fields for comprehensive profile management

-- Add new columns to existing users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone STRING DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS date_of_birth DATE DEFAULT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS gender STRING DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS address_line1 STRING DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS address_line2 STRING DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS city STRING DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS state STRING DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS zip_code STRING DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS country STRING DEFAULT 'United States';
ALTER TABLE users ADD COLUMN IF NOT EXISTS occupation STRING DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS employer STRING DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS annual_income DECIMAL(15,2) DEFAULT 0.00;
ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_image_url STRING DEFAULT '/static/profilepic.jpeg';
ALTER TABLE users ADD COLUMN IF NOT EXISTS preferred_language STRING DEFAULT 'English';
ALTER TABLE users ADD COLUMN IF NOT EXISTS time_zone STRING DEFAULT 'UTC';
ALTER TABLE users ADD COLUMN IF NOT EXISTS notification_preferences STRING DEFAULT 'email,sms';
ALTER TABLE users ADD COLUMN IF NOT EXISTS security_question STRING DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS security_answer STRING DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS emergency_contact_name STRING DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS emergency_contact_phone STRING DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS emergency_contact_relationship STRING DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS account_status STRING DEFAULT 'active';
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP DEFAULT NOW();
ALTER TABLE users ADD COLUMN IF NOT EXISTS login_count INT DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INT DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_completion_percentage INT DEFAULT 30;

-- Update existing test users with enhanced profile data
UPDATE users SET 
    phone = '555-0101',
    date_of_birth = '1990-05-15',
    gender = 'Male',
    address_line1 = '123 Main Street',
    city = 'New York',
    state = 'NY',
    zip_code = '10001',
    occupation = 'Software Engineer',
    employer = 'Tech Corp',
    annual_income = 75000.00,
    preferred_language = 'English',
    time_zone = 'America/New_York',
    emergency_contact_name = 'Jane Doe',
    emergency_contact_phone = '555-0102',
    emergency_contact_relationship = 'Sister',
    profile_completion_percentage = 85
WHERE username = 'johndoe';

UPDATE users SET 
    phone = '555-0201',
    date_of_birth = '1988-12-22',
    gender = 'Female',
    address_line1 = '456 Oak Avenue',
    city = 'Los Angeles',
    state = 'CA',
    zip_code = '90210',
    occupation = 'Marketing Manager',
    employer = 'Creative Agency',
    annual_income = 65000.00,
    preferred_language = 'English',
    time_zone = 'America/Los_Angeles',
    emergency_contact_name = 'Bob Smith',
    emergency_contact_phone = '555-0202',
    emergency_contact_relationship = 'Spouse',
    profile_completion_percentage = 90
WHERE username = 'janesmith';

UPDATE users SET 
    phone = '555-0301',
    date_of_birth = '1985-03-10',
    gender = 'Male',
    address_line1 = '789 Admin Street',
    city = 'Washington',
    state = 'DC',
    zip_code = '20001',
    occupation = 'System Administrator',
    employer = 'Government Agency',
    annual_income = 95000.00,
    preferred_language = 'English',
    time_zone = 'America/New_York',
    security_question = 'What is your favorite color?',
    security_answer = 'blue',
    emergency_contact_name = 'Sarah Admin',
    emergency_contact_phone = '555-0302',
    emergency_contact_relationship = 'Spouse',
    profile_completion_percentage = 95
WHERE username = 'admin';

UPDATE users SET 
    phone = '555-0401',
    date_of_birth = '1982-07-28',
    gender = 'Male',
    address_line1 = '999 Super Street',
    city = 'San Francisco',
    state = 'CA',
    zip_code = '94101',
    occupation = 'Chief Technology Officer',
    employer = 'Bank of Roachathon',
    annual_income = 150000.00,
    preferred_language = 'English',
    time_zone = 'America/Los_Angeles',
    security_question = 'What is your mother maiden name?',
    security_answer = 'SuperSecret',
    emergency_contact_name = 'Super Contact',
    emergency_contact_phone = '555-0402',
    emergency_contact_relationship = 'Business Partner',
    profile_completion_percentage = 100
WHERE username = 'superadmin'; 