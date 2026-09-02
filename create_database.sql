-- Vulnerable Banking Application Database Schema
-- This creates all tables needed for the educational security demo

-- Connect to bank database first
-- USE bank;

-- Users table for authentication and profile management
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    first_name STRING NOT NULL,
    last_name STRING NOT NULL, 
    username STRING UNIQUE NOT NULL,
    email STRING UNIQUE NOT NULL,
    password_hash STRING NOT NULL,
    bio STRING DEFAULT '',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Accounts table for banking operations
CREATE TABLE IF NOT EXISTS accounts (
    id SERIAL PRIMARY KEY,
    account_number STRING UNIQUE NOT NULL,
    user_id INT NOT NULL,
    account_type STRING DEFAULT 'checking',
    balance DECIMAL(15,2) DEFAULT 0.00,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Transactions table for banking history
CREATE TABLE IF NOT EXISTS transactions (
    id SERIAL PRIMARY KEY,
    from_account_id INT,
    to_account_id INT,
    amount DECIMAL(15,2) NOT NULL,
    transaction_type STRING NOT NULL, -- 'transfer', 'deposit', 'withdrawal', 'benefit'
    description STRING,
    status STRING DEFAULT 'completed', -- 'pending', 'completed', 'failed'
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (from_account_id) REFERENCES accounts(id),
    FOREIGN KEY (to_account_id) REFERENCES accounts(id)
);

-- Benefits table for tracking applied benefits
CREATE TABLE IF NOT EXISTS benefits (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    benefit_type STRING NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    applied_by INT, -- user_id of who applied it (for admin tracking)
    applied_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (applied_by) REFERENCES users(id)
);

-- Insert sample data for testing vulnerabilities

-- Sample users (including admin users with IDs divisible by 10)
INSERT INTO users (id, first_name, last_name, username, email, password_hash, bio) VALUES 
(1, 'John', 'Doe', 'johndoe', 'john@example.com', 'scrypt:32768:8:1$FBOwiJIO0KGOKqmv$c75cceb250194d9e154eadc3a14f846b094a07b8f602c38192890be7c046f02d0c8500252a201c488904e424b7343726eed1fd1350e0417cc75d83c1e0f2f37f', 'Regular user for testing'),
(2, 'Jane', 'Smith', 'janesmith', 'jane@example.com', 'scrypt:32768:8:1$FBOwiJIO0KGOKqmv$c75cceb250194d9e154eadc3a14f846b094a07b8f602c38192890be7c046f02d0c8500252a201c488904e424b7343726eed1fd1350e0417cc75d83c1e0f2f37f', 'Another test user'),
(10, 'Admin', 'User', 'admin', 'admin@bank.com', 'scrypt:32768:8:1$FBOwiJIO0KGOKqmv$c75cceb250194d9e154eadc3a14f846b094a07b8f602c38192890be7c046f02d0c8500252a201c488904e424b7343726eed1fd1350e0417cc75d83c1e0f2f37f', 'System administrator'),
(20, 'Super', 'Admin', 'superadmin', 'super@bank.com', 'scrypt:32768:8:1$FBOwiJIO0KGOKqmv$c75cceb250194d9e154eadc3a14f846b094a07b8f602c38192890be7c046f02d0c8500252a201c488904e424b7343726eed1fd1350e0417cc75d83c1e0f2f37f', 'Super administrator'),
(3, 'Test', 'User', 'testuser', 'test@example.com', 'scrypt:32768:8:1$FBOwiJIO0KGOKqmv$c75cceb250194d9e154eadc3a14f846b094a07b8f602c38192890be7c046f02d0c8500252a201c488904e424b7343726eed1fd1350e0417cc75d83c1e0f2f37f', 'Test user account')
ON CONFLICT (id) DO NOTHING;

-- Sample accounts for testing transfers and vulnerabilities
INSERT INTO accounts (account_number, user_id, account_type, balance) VALUES 
('123456789', 1, 'checking', 5000.00),
('987654321', 2, 'savings', 10000.00),
('555666777', 10, 'checking', 50000.00),
('111222333', 20, 'checking', 100000.00),
('444555666', 3, 'checking', 2500.00),
('777888999', 1, 'savings', 15000.00)
ON CONFLICT (account_number) DO NOTHING;

-- Sample transactions (including some with XSS payloads for export testing)
INSERT INTO transactions (from_account_id, to_account_id, amount, transaction_type, description) VALUES 
(1, 2, 100.00, 'transfer', 'Regular transfer'),
(2, 1, 50.00, 'transfer', 'Salary payment'),
(NULL, 1, 2500.00, 'deposit', 'Monthly salary'),
(1, NULL, 25.00, 'withdrawal', 'ATM withdrawal'),
(NULL, 2, 500.00, 'benefit', 'Loyalty bonus'),
-- XSS payload examples for export vulnerabilities
(1, 2, 75.00, 'transfer', '<script>alert("XSS in transaction!")</script>'),
(2, 1, 30.00, 'transfer', 'Payment <img src=x onerror=alert("XSS")>'),
(NULL, 3, 1000.00, 'deposit', 'Bonus <svg onload=alert("XSS")></svg>')
ON CONFLICT DO NOTHING;

-- Sample benefits for testing authorization
INSERT INTO benefits (user_id, benefit_type, amount, applied_by) VALUES 
(1, 'loyalty_bonus', 100.00, 10),
(2, 'cashback', 50.00, 10),
(3, 'interest_bonus', 25.00, 20)
ON CONFLICT DO NOTHING;

-- Show created tables and sample data
SELECT 'Tables created successfully' as status;
SELECT 'Users table:' as info, COUNT(*) as count FROM users;
SELECT 'Accounts table:' as info, COUNT(*) as count FROM accounts;
SELECT 'Transactions table:' as info, COUNT(*) as count FROM transactions;
SELECT 'Benefits table:' as info, COUNT(*) as count FROM benefits; 