-- ================================================================
-- TezGo — PostgreSQL schema (v1)
-- Made by CoreStack Labs
-- Covers: customers, drivers (+ documents), daily selfie check-ins,
--         orders, per-order chat (text+image), ratings, admins.
-- ================================================================

-- ---------- Customers (from @TezGO_bot) ----------
CREATE TABLE IF NOT EXISTS customers (
    id           BIGSERIAL PRIMARY KEY,
    telegram_id  BIGINT UNIQUE NOT NULL,
    name         TEXT,
    username     TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- Drivers (from @TezGoDriver_bot) ----------
-- Documents are stored as Telegram file_id strings (free storage on Telegram).
CREATE TABLE IF NOT EXISTS drivers (
    id                BIGSERIAL PRIMARY KEY,
    telegram_id       BIGINT UNIQUE NOT NULL,
    full_name         TEXT,
    username          TEXT,
    phone             TEXT,
    -- driver's licence
    license_front     TEXT,
    license_back      TEXT,
    -- vehicle tech passport
    techpass_front    TEXT,
    techpass_back     TEXT,
    -- taxi licence
    taxi_license      TEXT,
    -- car photos: 4 sides + interior
    car_photo_front   TEXT,
    car_photo_back    TEXT,
    car_photo_left    TEXT,
    car_photo_right   TEXT,
    car_photo_interior TEXT,
    -- car details
    car_make          TEXT,
    car_color         TEXT,
    car_plate         TEXT,
    -- lifecycle
    status            TEXT NOT NULL DEFAULT 'pending',  -- pending|approved|rejected|blocked
    reject_reason     TEXT,
    rating_avg        NUMERIC(3,2) NOT NULL DEFAULT 0,
    rides_done        INTEGER NOT NULL DEFAULT 0,
    is_online         BOOLEAN NOT NULL DEFAULT false,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at       TIMESTAMPTZ,
    approved_by       BIGINT
);

-- ---------- Daily selfie check-in ----------
-- A driver must submit an approved selfie for the current day to accept orders.
CREATE TABLE IF NOT EXISTS driver_checkins (
    id             BIGSERIAL PRIMARY KEY,
    driver_id      BIGINT NOT NULL REFERENCES drivers(id) ON DELETE CASCADE,
    day            DATE NOT NULL,
    selfie_file_id TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending',   -- pending|approved|rejected
    reviewed_by    BIGINT,
    reviewed_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (driver_id, day)
);

-- ---------- Orders ----------
CREATE TABLE IF NOT EXISTS orders (
    id             BIGSERIAL PRIMARY KEY,
    code           TEXT UNIQUE NOT NULL,               -- e.g. TG-8F3K2Q
    customer_id    BIGINT REFERENCES customers(id),
    driver_id      BIGINT REFERENCES drivers(id),
    pickup_lat     DOUBLE PRECISION,
    pickup_lon     DOUBLE PRECISION,
    pickup_address TEXT,
    dest_lat       DOUBLE PRECISION,
    dest_lon       DOUBLE PRECISION,
    dest_address   TEXT,
    car_class      TEXT,                               -- economy|comfort|business
    distance_km    NUMERIC(6,2),
    duration_min   INTEGER,
    fare_som       INTEGER,
    status         TEXT NOT NULL DEFAULT 'pending',    -- pending|accepted|enroute|arrived|completed|cancelled
    cancelled_by   TEXT,                               -- customer|driver|system
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    accepted_at    TIMESTAMPTZ,
    completed_at   TIMESTAMPTZ
);

-- ---------- Per-order chat (text + image), fully stored ----------
CREATE TABLE IF NOT EXISTS messages (
    id           BIGSERIAL PRIMARY KEY,
    order_id     BIGINT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    sender_role  TEXT NOT NULL,                        -- customer|driver
    sender_id    BIGINT,                               -- telegram_id of sender
    type         TEXT NOT NULL DEFAULT 'text',         -- text|image
    body         TEXT,                                 -- text content (for type=text)
    image_url    TEXT,                                 -- stored image path/url (for type=image)
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- Ratings ----------
CREATE TABLE IF NOT EXISTS ratings (
    id           BIGSERIAL PRIMARY KEY,
    order_id     BIGINT UNIQUE NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    driver_id    BIGINT REFERENCES drivers(id),
    customer_id  BIGINT REFERENCES customers(id),
    stars        INTEGER NOT NULL CHECK (stars BETWEEN 1 AND 5),
    comment      TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- Chat image blobs (kept out of messages to keep it light) ----------
CREATE TABLE IF NOT EXISTS chat_images (
    message_id  BIGINT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    mime        TEXT NOT NULL DEFAULT 'image/jpeg',
    data        BYTEA NOT NULL
);

-- ---------- Admins (web panel login) ----------
CREATE TABLE IF NOT EXISTS admins (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,                       -- bcrypt/argon2 hash, never plaintext
    name          TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- Indexes ----------
CREATE INDEX IF NOT EXISTS idx_orders_status    ON orders(status);
CREATE INDEX IF NOT EXISTS idx_orders_customer  ON orders(customer_id);
CREATE INDEX IF NOT EXISTS idx_orders_driver    ON orders(driver_id);
CREATE INDEX IF NOT EXISTS idx_orders_created   ON orders(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_order   ON messages(order_id, created_at);
CREATE INDEX IF NOT EXISTS idx_checkins_driver  ON driver_checkins(driver_id, day);
CREATE INDEX IF NOT EXISTS idx_drivers_status   ON drivers(status);
