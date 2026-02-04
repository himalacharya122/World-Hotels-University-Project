-- Temporary Form Data Table
CREATE TABLE temp_form_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(64) NOT NULL,
    form_data TEXT NOT NULL,
    expiry DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX (token),
    INDEX (expiry)
);

-- Currency Table
CREATE TABLE currencies (
    currency_id INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(3) NOT NULL,
    name VARCHAR(50) NOT NULL,
    symbol VARCHAR(5) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);

-- Core Tables
CREATE TABLE hotels (
    hotel_id INT AUTO_INCREMENT PRIMARY KEY,
    city VARCHAR(100) NOT NULL,
    hotel_name VARCHAR(100) NOT NULL,
    address TEXT NOT NULL,
    hotel_image VARCHAR(255),
    title VARCHAR(200),
    description TEXT,
    contact_number VARCHAR(20),
    email VARCHAR(100),
    check_in_time TIME DEFAULT '14:00:00',
    check_out_time TIME DEFAULT '11:00:00',
    status ENUM('active', 'inactive') DEFAULT 'active',
    total_capacity INT NOT NULL DEFAULT 0,
    standard_rooms INT NOT NULL DEFAULT 0,
    double_rooms INT NOT NULL DEFAULT 0,
    family_rooms INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE room_types (
    room_type_id INT AUTO_INCREMENT PRIMARY KEY,
    type_name ENUM('Standard', 'Double', 'Family') NOT NULL,
    base_price_multiplier DECIMAL(4,2) NOT NULL,
    max_occupancy INT NOT NULL,
    description TEXT,
    distribution_percentage DECIMAL(5,2) DEFAULT 33.33,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE rooms (
    room_id INT AUTO_INCREMENT PRIMARY KEY,
    hotel_id INT NOT NULL,
    room_type_id INT NOT NULL,
    room_number VARCHAR(10) NOT NULL,
    floor_number INT NOT NULL,
    base_price DECIMAL(10,2) NOT NULL,
    room_image VARCHAR(255),
    status ENUM('available', 'booked', 'maintenance') DEFAULT 'available',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (hotel_id) REFERENCES hotels(hotel_id),
    FOREIGN KEY (room_type_id) REFERENCES room_types(room_type_id),
    UNIQUE KEY unique_room_hotel (hotel_id, room_number)
);

CREATE TABLE room_features (
    feature_id INT AUTO_INCREMENT PRIMARY KEY,
    feature_name VARCHAR(50) NOT NULL,
    description TEXT,
    icon_class VARCHAR(50)
);

CREATE TABLE room_feature_mapping (
    mapping_id INT AUTO_INCREMENT PRIMARY KEY,
    room_id INT NOT NULL,
    feature_id INT NOT NULL,
    FOREIGN KEY (room_id) REFERENCES rooms(room_id),
    FOREIGN KEY (feature_id) REFERENCES room_features(feature_id),
    UNIQUE KEY unique_room_feature (room_id, feature_id)
);

-- User Management Tables
CREATE TABLE user_roles (
    role_id INT AUTO_INCREMENT PRIMARY KEY,
    role_name ENUM('admin', 'customer', 'staff') NOT NULL,
    permissions TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    role_id INT NOT NULL,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    phone_number VARCHAR(20),
    profile_image VARCHAR(255),
    address TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    last_login DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES user_roles(role_id)
);

-- Booking Related Tables
CREATE TABLE bookings (
    booking_id INT AUTO_INCREMENT PRIMARY KEY,
    booking_reference VARCHAR(20) UNIQUE NOT NULL,
    user_id INT NOT NULL,
    hotel_id INT NOT NULL,
    room_id INT NOT NULL,
    currency_id INT NOT NULL,
    check_in_date DATE NOT NULL,
    check_out_date DATE NOT NULL,
    number_of_guests INT NOT NULL,
    special_requests TEXT,
    total_amount DECIMAL(10,2) NOT NULL,
    discount_amount DECIMAL(10,2) DEFAULT 0,
    final_amount DECIMAL(10,2) NOT NULL,
    booking_date DATETIME NOT NULL,
    status ENUM('pending', 'confirmed', 'cancelled') DEFAULT 'pending',
    cancellation_charge DECIMAL(10,2) DEFAULT 0,
    payment_status ENUM('pending', 'paid', 'refunded') DEFAULT 'pending',
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (hotel_id) REFERENCES hotels(hotel_id),
    FOREIGN KEY (room_id) REFERENCES rooms(room_id),
    FOREIGN KEY (currency_id) REFERENCES currencies(currency_id)
);

CREATE TABLE booking_details (
    detail_id INT AUTO_INCREMENT PRIMARY KEY,
    booking_id INT NOT NULL,
    guest_name VARCHAR(100) NOT NULL,
    guest_email VARCHAR(100) NOT NULL,
    guest_phone VARCHAR(20),
    is_primary_guest BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (booking_id) REFERENCES bookings(booking_id)
);

-- Pricing & Rate Tables
CREATE TABLE seasonal_rates (
    rate_id INT AUTO_INCREMENT PRIMARY KEY,
    hotel_id INT NOT NULL,
    room_type_id INT NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    is_peak_season BOOLEAN DEFAULT FALSE,
    base_price DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (hotel_id) REFERENCES hotels(hotel_id),
    FOREIGN KEY (room_type_id) REFERENCES room_types(room_type_id)
);

CREATE TABLE advance_booking_discount (
    discount_id INT AUTO_INCREMENT PRIMARY KEY,
    min_days INT NOT NULL,
    max_days INT NOT NULL,
    discount_percentage DECIMAL(5,2) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE exchange_rates (
    rate_id INT AUTO_INCREMENT PRIMARY KEY,
    from_currency_id INT NOT NULL,
    to_currency_id INT NOT NULL,
    rate DECIMAL(10,6) NOT NULL,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (from_currency_id) REFERENCES currencies(currency_id),
    FOREIGN KEY (to_currency_id) REFERENCES currencies(currency_id)
);

-- Authentication & Security Tables
CREATE TABLE user_sessions (
    session_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE password_reset_tokens (
    token_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE email_verification (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    INDEX (token),
    INDEX (expires_at)
);

-- Cancellation & Status Tables
CREATE TABLE cancellation_policies (
    policy_id INT AUTO_INCREMENT PRIMARY KEY,
    days_before_checkin INT NOT NULL,
    charge_percentage DECIMAL(5,2) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE booking_status_history (
    history_id INT AUTO_INCREMENT PRIMARY KEY,
    booking_id INT NOT NULL,
    status ENUM('pending', 'confirmed', 'cancelled') NOT NULL,
    changed_by_user_id INT NOT NULL,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,
    FOREIGN KEY (booking_id) REFERENCES bookings(booking_id),
    FOREIGN KEY (changed_by_user_id) REFERENCES users(user_id)
);

-- Transaction & Audit Tables
CREATE TABLE booking_transactions (
    transaction_id INT AUTO_INCREMENT PRIMARY KEY,
    booking_id INT NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    transaction_type ENUM('payment', 'refund') NOT NULL,
    status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
    payment_method VARCHAR(50),
    transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (booking_id) REFERENCES bookings(booking_id)
);

CREATE TABLE audit_logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(100) NOT NULL,
    table_name VARCHAR(50) NOT NULL,
    record_id INT,
    old_values JSON,
    new_values JSON,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Additional Features Tables
CREATE TABLE hotel_amenities (
    amenity_id INT AUTO_INCREMENT PRIMARY KEY,
    hotel_id INT NOT NULL,
    amenity_name VARCHAR(100) NOT NULL,
    description TEXT,
    icon_class VARCHAR(50),
    FOREIGN KEY (hotel_id) REFERENCES hotels(hotel_id)
);

-- Gallery Tables
CREATE TABLE gallery (
    gallery_id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(100),
    image_url VARCHAR(500) NOT NULL,
    category VARCHAR(50),
    description TEXT,
    hotel_id INT,
    display_order INT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (hotel_id) REFERENCES hotels(hotel_id)
);


-- Newsletter Tables
CREATE TABLE newsletter_subscribers (
    subscriber_id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(100) UNIQUE NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMP NULL,
    subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_subscriber_email (email),
    INDEX idx_subscriber_status (is_active)
);

CREATE TABLE newsletter_audit_log (
    audit_id INT AUTO_INCREMENT PRIMARY KEY,
    subscriber_id INT,
    action ENUM('subscribe', 'unsubscribe', 'bounce') NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (subscriber_id) REFERENCES newsletter_subscribers(subscriber_id)
);

CREATE TABLE notifications (
    notification_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    type VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Contact Messages Table
CREATE TABLE contact_messages (
    message_id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    subject VARCHAR(200) NOT NULL,
    message TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    status ENUM('new', 'read', 'replied') DEFAULT 'new',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);


-- Indexes
ALTER TABLE rooms ADD INDEX idx_room_status (status);
ALTER TABLE bookings ADD INDEX idx_booking_dates (check_in_date, check_out_date);
ALTER TABLE users ADD INDEX idx_user_email (email);
ALTER TABLE seasonal_rates ADD INDEX idx_seasonal_dates (start_date, end_date);
ALTER TABLE bookings ADD INDEX idx_booking_reference (booking_reference);
ALTER TABLE notifications ADD INDEX idx_unread_notifications (user_id, is_read);
ALTER TABLE booking_transactions ADD INDEX idx_transaction_date (transaction_date);
ALTER TABLE gallery ADD INDEX idx_gallery_category (category);
ALTER TABLE gallery ADD INDEX idx_gallery_hotel (hotel_id);

-- Triggers
DELIMITER //

-- After Insert Booking Trigger
CREATE TRIGGER after_booking_insert 
AFTER INSERT ON bookings
FOR EACH ROW
BEGIN
    -- Update room status
    UPDATE rooms SET status = 'booked' WHERE room_id = NEW.room_id;
    
    -- Create notification for user
    INSERT INTO notifications (user_id, type, message)
    VALUES (NEW.user_id, 'booking_confirmation', 
            CONCAT('Your booking ', NEW.booking_reference, ' has been confirmed'));
    
    -- Create audit log
    INSERT INTO audit_logs (user_id, action, table_name, record_id, new_values)
    VALUES (NEW.user_id, 'create_booking', 'bookings', NEW.booking_id, 
            JSON_OBJECT('booking_id', NEW.booking_id, 'status', NEW.status));
END//

-- After Update Booking Trigger (for cancellations)
CREATE TRIGGER after_booking_update 
AFTER UPDATE ON bookings
FOR EACH ROW
BEGIN
    IF NEW.status = 'cancelled' AND OLD.status != 'cancelled' THEN
        -- Update room status
        UPDATE rooms SET status = 'available' WHERE room_id = NEW.room_id;
        
        -- Create refund record if payment was made
        IF OLD.payment_status = 'paid' THEN
            INSERT INTO booking_transactions (booking_id, amount, transaction_type, status)
            VALUES (NEW.booking_id, NEW.final_amount, 'refund', 'pending');
        END IF;
    END IF;
END//

-- Before Insert Seasonal Rates Trigger (prevent overlapping dates)
CREATE TRIGGER before_seasonal_rates_insert
BEFORE INSERT ON seasonal_rates
FOR EACH ROW
BEGIN
    DECLARE overlap_count INT;
    
    SELECT COUNT(*) INTO overlap_count
    FROM seasonal_rates
    WHERE hotel_id = NEW.hotel_id
    AND room_type_id = NEW.room_type_id
    AND ((NEW.start_date BETWEEN start_date AND end_date)
    OR (NEW.end_date BETWEEN start_date AND end_date));
    
    IF overlap_count > 0 THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Date range overlaps with existing seasonal rates';
    END IF;
END//

-- Before Gallery Insert Trigger (maintain display order)
CREATE TRIGGER before_gallery_insert 
BEFORE INSERT ON gallery
FOR EACH ROW
BEGIN
    IF NEW.display_order = 0 THEN
        SET NEW.display_order = (
            SELECT COALESCE(MAX(display_order), 0) + 1 
            FROM gallery 
            WHERE hotel_id = NEW.hotel_id
        );
    END IF;
END//

-- Before User Delete Trigger (prevent admin deletion if last admin)
CREATE TRIGGER before_user_delete
BEFORE DELETE ON users
FOR EACH ROW
BEGIN
    DECLARE admin_count INT;
    
    IF (SELECT role_name FROM user_roles WHERE role_id = OLD.role_id) = 'admin' THEN
        SELECT COUNT(*) INTO admin_count 
        FROM users u 
        JOIN user_roles r ON u.role_id = r.role_id 
        WHERE r.role_name = 'admin' AND u.is_active = TRUE;
        
        IF admin_count <= 1 THEN
            SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Cannot delete the last active admin user';
        END IF;
    END IF;
END//

-- After Room Update Trigger (log capacity changes)
CREATE TRIGGER after_room_update
AFTER UPDATE ON rooms
FOR EACH ROW
BEGIN
    IF NEW.status != OLD.status THEN
        INSERT INTO audit_logs (
            user_id,
            action,
            table_name,
            record_id,
            old_values,
            new_values
        )
        VALUES (
            NULL, -- System change
            'room_status_change',
            'rooms',
            NEW.room_id,
            JSON_OBJECT('status', OLD.status),
            JSON_OBJECT('status', NEW.status)
        );
    END IF;
END//

DELIMITER ;






























-- 1. Currencies (base currency is GBP)
INSERT INTO currencies (code, name, symbol, is_active) VALUES
('GBP', 'British Pound', '£', true),
('USD', 'US Dollar', '$', true),
('EUR', 'Euro', '€', true),
('AUD', 'Australian Dollar', 'A$', true),
('CAD', 'Canadian Dollar', 'C$', true);

-- 2. Exchange Rates (based on GBP)

-- Insert new exchange rates
INSERT INTO exchange_rates (from_currency_id, to_currency_id, rate) VALUES
(1, 2, 1.25),    -- GBP to USD
(1, 3, 1.15),    -- GBP to EUR
(1, 5, 1.90),    -- GBP to AUD
(1, 6, 1.70);    -- GBP to CAD;

INSERT INTO exchange_rates (from_currency_id, to_currency_id, rate) VALUES
-- From GBP (id: 1)
(1, 2, 1.25),    -- GBP to USD
(1, 3, 1.15),    -- GBP to EUR
(1, 5, 1.90),    -- GBP to AUD
(1, 6, 1.70),    -- GBP to CAD,

-- From USD (id: 2)
(2, 1, 0.80),    -- USD to GBP
(2, 3, 0.92),    -- USD to EUR
(2, 5, 1.52),    -- USD to AUD
(2, 6, 1.36),    -- USD to CAD,

-- From EUR (id: 3)
(3, 1, 0.87),    -- EUR to GBP
(3, 2, 1.09),    -- EUR to USD
(3, 5, 1.65),    -- EUR to AUD
(3, 6, 1.48),    -- EUR to CAD,

-- From AUD (id: 5)
(5, 1, 0.526),   -- AUD to GBP
(5, 2, 0.658),   -- AUD to USD
(5, 3, 0.606),   -- AUD to EUR
(5, 6, 0.895),   -- AUD to CAD,

-- From CAD (id: 6)
(6, 1, 0.588),   -- CAD to GBP
(6, 2, 0.735),   -- CAD to USD
(6, 3, 0.676),   -- CAD to EUR
(6, 5, 1.117);   -- CAD to AUD


-- 3. Room Types with price multipliers
INSERT INTO room_types (type_name, base_price_multiplier, max_occupancy, description, distribution_percentage) VALUES
('Standard', 1.00, 1, 'Comfortable room for single occupancy', 30.00),
('Double', 1.20, 2, 'Spacious room for two guests', 50.00),
('Family', 1.50, 4, 'Large room perfect for families', 20.00);

-- 4. Room Features (using Font Awesome icons)
INSERT INTO room_features (feature_name, description, icon_class) VALUES
('WiFi', 'High-speed wireless internet', 'fa-wifi'),
('TV', 'Flat-screen TV with cable channels', 'fa-tv'),
('Mini Bar', 'Well-stocked mini bar', 'fa-wine-glass'),
('Breakfast', 'Complimentary breakfast', 'fa-coffee'),
('Air Conditioning', 'Climate control', 'fa-snowflake'),
('Safe', 'In-room safe', 'fa-vault'),
('Room Service', '24/7 room service', 'fa-concierge-bell'),
('Phone', 'Direct dial telephone', 'fa-phone');

-- 5. Advance Booking Discount
INSERT INTO advance_booking_discount (min_days, max_days, discount_percentage) VALUES
(80, 90, 30.00),
(60, 79, 20.00),
(45, 59, 10.00),
(0, 44, 0.00);

-- 6. Cancellation Policies
INSERT INTO cancellation_policies (days_before_checkin, charge_percentage, is_active) VALUES
(60, 0.00, true),    -- No charge if cancelled 60+ days before
(30, 50.00, true),   -- 50% charge if cancelled 30-60 days before
(0, 100.00, true);   -- 100% charge if cancelled less than 30 days before

-- 7. User Roles
INSERT INTO user_roles (role_name, permissions) VALUES
('admin', 'all'),
('customer', 'booking,profile'),
('staff', 'booking,rooms');

-- 8. Admin User (password: admin123)
INSERT INTO users (role_id, first_name, last_name, email, password_hash, is_active) VALUES
(1, 'Admin', 'User', 'admin@worldhotels.com', 
'pbkdf2:sha256:600000$yYpt8GDSLdlFBoq8$7f98e98ba9d7bbffa956ef7bd94a1323de93c42dcddaf5a3a0708f005d79a893', true); -- Admin@123 --

-- 9. Hotels
INSERT INTO hotels (city, hotel_name, address, hotel_image, title, description, total_capacity, standard_rooms, double_rooms, family_rooms) VALUES
('London', 'World Hotel London', '123 Westminster Bridge Road, London', '/static/uploads/london.jpg', 
'Luxury Stay in London', 'Experience luxury in the heart of London with stunning views.', 
20, 6, 10, 4),

('Manchester', 'World Hotel Manchester', '45 Deansgate, Manchester', '/static/uploads/manchester.jpg',
'Urban Elegance', 'Modern luxury in Manchesters vibrant city center.',
20, 6, 10, 4),

('Edinburgh', 'World Hotel Edinburgh', '78 Royal Mile, Edinburgh', '/static/uploads/edinburgh.jpg',
'Scottish Heritage', 'Classic luxury with views of Edinburgh Castle.',
18, 5, 9, 4),

('Birmingham', 'World Hotel Birmingham', '56 Broad Street, Birmingham', '/static/uploads/birmingham.jpg',
'Contemporary Comfort', 'Modern amenities in Birminghams business district.',
18, 5, 9, 4),

('Glasgow', 'World Hotel Glasgow', '34 Buchanan Street, Glasgow', '/static/uploads/glasgow.jpg',
'Glasgow Grandeur', 'Elegant accommodation in the heart of Glasgow.',
20, 6, 10, 4),

('Bristol', 'World Hotel Bristol', '89 Queens Road, Bristol', '/static/uploads/bristol.jpg',
'Bristol Beauty', 'Charming hotel in Bristols historic quarter.',
16, 5, 8, 3),

('Cardiff', 'World Hotel Cardiff', '12 Castle Street, Cardiff', '/static/uploads/cardiff.jpg',
'Welsh Wonder', 'Luxury accommodation near Cardiff Castle.',
16, 5, 8, 3),

('Oxford', 'World Hotel Oxford', '67 High Street, Oxford', '/static/uploads/oxford.jpg',
'Academic Excellence', 'Classic elegance in the university city.',
16, 5, 8, 3),

('Aberdeen', 'World Hotel Aberdeen', '23 Union Street, Aberdeen', '/static/uploads/aberdeen.jpg',
'Granite City Grace', 'Luxury in the heart of Aberdeen.',
16, 5, 8, 3),

('Belfast', 'World Hotel Belfast', '45 Victoria Street, Belfast', '/static/uploads/belfast.jpg',
'Belfast Charm', 'Modern luxury in Northern Irelands capital.',
15, 4, 8, 3),

('Norwich', 'World Hotel Norwich', '34 Prince of Wales Road, Norwich', '/static/uploads/norwich.jpg',
'Norfolk Nobility', 'Elegant stay in historic Norwich.',
16, 5, 8, 3),

('Plymouth', 'World Hotel Plymouth', '78 Armada Way, Plymouth', '/static/uploads/plymouth.jpg',
'Coastal Comfort', 'Luxury with ocean views.',
15, 4, 8, 3),

('Nottingham', 'World Hotel Nottingham', '56 Derby Road, Nottingham', '/static/uploads/nottingham.jpg',
'Robin Hood Country', 'Historic luxury in Nottingham center.',
18, 5, 9, 4),

('Swansea', 'World Hotel Swansea', '12 Marina, Swansea', '/static/uploads/swansea.jpg',
'Welsh Waterfront', 'Luxury overlooking Swansea Bay.',
15, 4, 8, 3),

('Newcastle', 'World Hotel Newcastle', '89 Grey Street, Newcastle', '/static/uploads/newcastle.jpg',
'Tyne Elegance', 'Contemporary luxury on the Tyne.',
16, 5, 8, 3),

('Bournemouth', 'World Hotel Bournemouth', '23 West Cliff Road, Bournemouth', '/static/uploads/bournemouth.jpg',
'Coastal Luxury', 'Elegant accommodation by the sea.',
16, 5, 8, 3),

('Kent', 'World Hotel Kent', '45 High Street, Canterbury, Kent', '/static/uploads/kent.jpg',
'Garden of England', 'Historic luxury in the heart of Kent.',
18, 5, 9, 4);

-- 10. Rooms (15-20 per hotel)
-- 10. Rooms for multiple hotels (20 rooms each)
INSERT INTO rooms (hotel_id, room_type_id, room_number, floor_number, base_price, room_image, status)
SELECT 
    hotel_id,
    CASE 
        WHEN room_number <= 6 THEN 1  -- Standard rooms (30%)
        WHEN room_number <= 16 THEN 2 -- Double rooms (50%)
        ELSE 3                        -- Family rooms (20%)
    END as room_type_id,
    CONCAT(FLOOR((room_number-1)/5) + 1, LPAD(MOD(room_number-1,5) + 1, 2, '0')) as room_num,
    FLOOR((room_number-1)/5) + 1 as floor_num,
    CASE 
        -- London (hotel_id = 1)
        WHEN hotel_id = 1 AND room_number <= 6 THEN 200   -- Standard
        WHEN hotel_id = 1 AND room_number <= 16 THEN 240  -- Double
        WHEN hotel_id = 1 THEN 300                        -- Family
        
        -- Manchester (hotel_id = 2)
        WHEN hotel_id = 2 AND room_number <= 6 THEN 180   -- Standard
        WHEN hotel_id = 2 AND room_number <= 16 THEN 216  -- Double
        WHEN hotel_id = 2 THEN 270                        -- Family
        
        -- Edinburgh (hotel_id = 3)
        WHEN hotel_id = 3 AND room_number <= 6 THEN 160   -- Standard
        WHEN hotel_id = 3 AND room_number <= 16 THEN 192  -- Double
        WHEN hotel_id = 3 THEN 240                        -- Family
        
        -- Birmingham (hotel_id = 4)
        WHEN hotel_id = 4 AND room_number <= 6 THEN 150   -- Standard
        WHEN hotel_id = 4 AND room_number <= 16 THEN 180  -- Double
        WHEN hotel_id = 4 THEN 225                        -- Family
        
        -- Glasgow (hotel_id = 5)
        WHEN hotel_id = 5 AND room_number <= 6 THEN 150   -- Standard
        WHEN hotel_id = 5 AND room_number <= 16 THEN 180  -- Double
        WHEN hotel_id = 5 THEN 225                        -- Family
        
        -- Bristol (hotel_id = 6)
        WHEN hotel_id = 6 AND room_number <= 6 THEN 140   -- Standard
        WHEN hotel_id = 6 AND room_number <= 16 THEN 168  -- Double
        WHEN hotel_id = 6 THEN 210                        -- Family
        
        -- Cardiff (hotel_id = 7)
        WHEN hotel_id = 7 AND room_number <= 6 THEN 130   -- Standard
        WHEN hotel_id = 7 AND room_number <= 16 THEN 156  -- Double
        WHEN hotel_id = 7 THEN 195                        -- Family
    END as base_price,
    CASE 
        WHEN room_number <= 6 THEN '/static/uploads/standard.jpg'
        WHEN room_number <= 16 THEN '/static/uploads/double.jpg'
        ELSE '/static/uploads/family.jpg'
    END as room_image,
    'available' as status
FROM (
    -- Generate 20 rooms for each of the 7 hotels
    SELECT 
        a.hotel_id,
        b.room_number
    FROM (
        SELECT 1 as hotel_id UNION SELECT 2 UNION SELECT 3 UNION 
        SELECT 4 UNION SELECT 5 UNION SELECT 6 UNION SELECT 7
    ) a
    CROSS JOIN (
        SELECT ROW_NUMBER() OVER () as room_number 
        FROM information_schema.columns 
        LIMIT 20
    ) b
) hotel_rooms;

-- 11. Room Feature
-- Room Features with Font Awesome icons
INSERT INTO room_features (feature_name, description, icon_class) VALUES
-- Basic Amenities
('WiFi', 'High-speed wireless internet access', 'fa-wifi'),
('Air Conditioning', 'Individual climate control', 'fa-snowflake'),
('TV', '43" Smart TV with streaming services', 'fa-tv'),
('Phone', 'Direct dial telephone', 'fa-phone'),

-- Bathroom Features
('Hair Dryer', 'Professional hair dryer', 'fa-wind'),
('Toiletries', 'Premium bathroom amenities', 'fa-pump-soap'),

-- Food & Beverage
('Mini Bar', 'Well-stocked minibar', 'fa-wine-bottle'),
('Breakfast Included', 'Complimentary breakfast', 'fa-utensils');

-- 12. Seasonal Rates
-- Seasonal Rates for 7 hotels (both peak and off-peak seasons)
INSERT INTO seasonal_rates (hotel_id, room_type_id, start_date, end_date, is_peak_season, base_price)
SELECT 
    h.hotel_id,
    rt.room_type_id,
    season_date.start_date,
    season_date.end_date,
    season_date.is_peak,
    CASE 
        -- LONDON (Peak: 200/Off-peak: 100)
        WHEN h.city = 'London' AND season_date.is_peak THEN
            CASE 
                WHEN rt.type_name = 'Standard' THEN 200
                WHEN rt.type_name = 'Double' THEN 240
                ELSE 300
            END
        WHEN h.city = 'London' AND NOT season_date.is_peak THEN
            CASE 
                WHEN rt.type_name = 'Standard' THEN 100
                WHEN rt.type_name = 'Double' THEN 120
                ELSE 150
            END

        -- MANCHESTER (Peak: 180/Off-peak: 90)
        WHEN h.city = 'Manchester' AND season_date.is_peak THEN
            CASE 
                WHEN rt.type_name = 'Standard' THEN 180
                WHEN rt.type_name = 'Double' THEN 216
                ELSE 270
            END
        WHEN h.city = 'Manchester' AND NOT season_date.is_peak THEN
            CASE 
                WHEN rt.type_name = 'Standard' THEN 90
                WHEN rt.type_name = 'Double' THEN 108
                ELSE 135
            END

        -- EDINBURGH (Peak: 160/Off-peak: 80)
        WHEN h.city = 'Edinburgh' AND season_date.is_peak THEN
            CASE 
                WHEN rt.type_name = 'Standard' THEN 160
                WHEN rt.type_name = 'Double' THEN 192
                ELSE 240
            END
        WHEN h.city = 'Edinburgh' AND NOT season_date.is_peak THEN
            CASE 
                WHEN rt.type_name = 'Standard' THEN 80
                WHEN rt.type_name = 'Double' THEN 96
                ELSE 120
            END

        -- BIRMINGHAM (Peak: 150/Off-peak: 75)
        WHEN h.city = 'Birmingham' AND season_date.is_peak THEN
            CASE 
                WHEN rt.type_name = 'Standard' THEN 150
                WHEN rt.type_name = 'Double' THEN 180
                ELSE 225
            END
        WHEN h.city = 'Birmingham' AND NOT season_date.is_peak THEN
            CASE 
                WHEN rt.type_name = 'Standard' THEN 75
                WHEN rt.type_name = 'Double' THEN 90
                ELSE 112.5
            END

        -- GLASGOW (Peak: 150/Off-peak: 75)
        WHEN h.city = 'Glasgow' AND season_date.is_peak THEN
            CASE 
                WHEN rt.type_name = 'Standard' THEN 150
                WHEN rt.type_name = 'Double' THEN 180
                ELSE 225
            END
        WHEN h.city = 'Glasgow' AND NOT season_date.is_peak THEN
            CASE 
                WHEN rt.type_name = 'Standard' THEN 75
                WHEN rt.type_name = 'Double' THEN 90
                ELSE 112.5
            END

        -- BRISTOL (Peak: 140/Off-peak: 70)
        WHEN h.city = 'Bristol' AND season_date.is_peak THEN
            CASE 
                WHEN rt.type_name = 'Standard' THEN 140
                WHEN rt.type_name = 'Double' THEN 168
                ELSE 210
            END
        WHEN h.city = 'Bristol' AND NOT season_date.is_peak THEN
            CASE 
                WHEN rt.type_name = 'Standard' THEN 70
                WHEN rt.type_name = 'Double' THEN 84
                ELSE 105
            END

        -- CARDIFF (Peak: 130/Off-peak: 70)
        WHEN h.city = 'Cardiff' AND season_date.is_peak THEN
            CASE 
                WHEN rt.type_name = 'Standard' THEN 130
                WHEN rt.type_name = 'Double' THEN 156
                ELSE 195
            END
        WHEN h.city = 'Cardiff' AND NOT season_date.is_peak THEN
            CASE 
                WHEN rt.type_name = 'Standard' THEN 70
                WHEN rt.type_name = 'Double' THEN 84
                ELSE 105
            END
    END
FROM hotels h
CROSS JOIN room_types rt
CROSS JOIN (
    -- Peak Seasons
    SELECT '2024-04-01' as start_date, '2024-08-31' as end_date, TRUE as is_peak UNION
    SELECT '2024-11-01', '2024-12-31', TRUE UNION
    -- Off-peak Seasons
    SELECT '2024-01-01', '2024-03-31', FALSE UNION
    SELECT '2024-09-01', '2024-10-31', FALSE
) season_date
WHERE h.hotel_id <= 7;  -- Only for first 7 hotels

-- 13. Hotel Amenities (using Font Awesome icons)
INSERT INTO hotel_amenities (hotel_id, amenity_name, description, icon_class) VALUES
(1, 'Swimming Pool', 'Indoor heated pool', 'fa-swimming-pool'),
(1, 'Fitness Center', '24/7 gym access', 'fa-dumbbell'),
(1, 'Restaurant', 'Fine dining experience', 'fa-utensils'),
(1, 'Spa', 'Luxury spa treatments', 'fa-spa'),
(1, 'Conference Room', 'Business facilities', 'fa-presentation'),
(1, 'Parking', 'Secure underground parking', 'fa-parking'),
(1, 'Bar', 'Elegant cocktail bar', 'fa-glass-martini-alt'),
(1, 'Room Service', '24-hour room service', 'fa-concierge-bell');

INSERT INTO hotel_amenities (hotel_id, amenity_name, description, icon_class) VALUES
(4, 'Swimming Pool', 'Indoor heated pool', 'fa-swimming-pool'),
(4, 'Fitness Center', '24/7 gym access', 'fa-dumbbell'),
(4, 'Restaurant', 'Fine dining experience', 'fa-utensils'),
(4, 'Spa', 'Luxury spa treatments', 'fa-spa'),
(4, 'Conference Room', 'Business facilities', 'fa-presentation'),
(4, 'Parking', 'Secure underground parking', 'fa-parking'),
(4, 'Bar', 'Elegant cocktail bar', 'fa-glass-martini-alt'),
(4, 'Room Service', '24-hour room service', 'fa-concierge-bell');



-- Insert data into the gallery table
INSERT INTO gallery (title, image_url, category, description, hotel_id, display_order, is_active) VALUES
('Deluxe Room View', '/static/gallery_images/deluxe-room.jpg', 'Rooms', 'A cozy deluxe room with a beautiful view.', 1, 1, TRUE),
('Poolside Area', '/static/gallery_images/poolside.jpg', 'Amenities', 'Relax by the poolside and enjoy the sunshine.', 1, 2, TRUE),
('Restaurant Dining', '/static/gallery_images/restaurant.jpg', 'Dining', 'Our restaurant offers a variety of local and international cuisines.', 2, 3, TRUE),
('Conference Hall', '/static/gallery_images/conference-hall.jpg', 'Facilities', 'A spacious conference hall for meetings and events.', 7, 1, TRUE),
('Lobby Entrance', '/static/gallery_images/lobby.jpg', 'Interior', 'Our elegant lobby welcomes you to a luxurious experience.', 3, 2, TRUE),
('Spa and Wellness', '/static/gallery_images/spa.jpg', 'Amenities', 'Unwind and rejuvenate at our full-service spa.', 4, 1, TRUE),
('Family Suite', '/static/gallery_images/family-suite.jpg', 'Rooms', 'A spacious suite perfect for families.', 5, 2, TRUE),
('Rooftop View', '/static/gallery_images/rooftop.jpg', 'Scenic', 'Enjoy a stunning view of the city from our rooftop.', 6, 3, TRUE);