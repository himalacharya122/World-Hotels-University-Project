# Hotel Management System

## Description
The Hotel Management System is a web application designed to streamline the management of hotel operations. It provides functionalities for hotel bookings, user management, and administrative tasks, making it easier for hotel staff to manage their services efficiently.

## Features
- User authentication (login, registration, password reset)
- Hotel and room management (add, edit, delete hotels and rooms)
- Booking management (search for hotels, book rooms, view booking history)
- Admin dashboard for managing users, hotels, and bookings
- Responsive design accross all devices
- All of the secured validation for forms and login registers
- Email notifications for booking confirmations and more alerts
- Error handling for common issues (404, 500 errors)
- User roles (admin, customer)
- Payment processing integration (fake payments accepted)
- Search and more filters for all managements and bookings systems
- Booking cancellation and modification options
- Gallery for hotel images
- Contact forms for inquiries and support
- Terms and conditions, privacy policy pages
- Analytics dashboard for tracking bookings and user activity
- Most of the data are exportable in pdf and excel sheet
- Many more small features

## Installation
To set up the project locally, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/hotel-management-system.git
   cd hotel-management-system
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up the database:
   - Import the `database.sql` file into your SQL database.

4. Configure the application:
   - Update the configuration settings in `config/config.py` as needed.

5. Run the application:
   ```bash
   python app.py
   ```

## Usage
Once the application is running, you can access it in your web browser at `http://localhost:5000`. You can register as a new user or log in with existing credentials to start managing hotel bookings.