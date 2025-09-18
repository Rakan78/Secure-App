DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role') THEN
        CREATE TYPE user_role AS ENUM ('user', 'admin', 'super');
    END IF;
END$$;

CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role user_role NOT NULL DEFAULT 'user' 
);

CREATE TABLE IF NOT EXISTS posts (
    id SERIAL PRIMARY KEY,
    post_owner TEXT NOT NULL,
    content TEXT NOT NULL,
    FOREIGN KEY (post_owner) REFERENCES users(username)
);

INSERT INTO users (name, username, password, email, role) 
VALUES 
('admin', 'admin', '$2b$10$FgGAE4vulwnrBDpvF0ZAPuHukg6eH6mvNBwnEmMaj7hVNRUQdkDT2', 'admin@admin.com', 'admin')
ON CONFLICT (username) DO NOTHING;
