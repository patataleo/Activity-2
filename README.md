# Brute Force Protection PHP Login System

## Overview
This project is a simple user login system built with PHP and MySQL that includes brute force protection.
It tracks login attempts and blocks users after 5 failed attempts, requiring them to wait 5 minutes before trying again.

## Features

### User Login Interface
A simple form where users can enter their username and password to log in.
![Screenshot 2025-04-28 185831](https://github.com/user-attachments/assets/fd136db8-8fd5-4eb2-abdb-9b58ad6b9bea)

### Successful Login Notification
Displays a message like:
`"Login successful!"`
![Screenshot 2025-04-28 185846](https://github.com/user-attachments/assets/0a2d2401-3958-495f-9255-33e758be797b)

### Failed Login Notification
Displays a message like:
`"Incorrect password."
"User not found."`
![Screenshot 2025-04-28 185858](https://github.com/user-attachments/assets/0a3e1966-96fa-465d-a999-53a2853924cf)

### Brute Force Protection
- If a user fails to login 5 times within 5 minutes, they are blocked temporarily.
- A prompt will appear:
`  "Too many failed attempts. Try again after 5 minutes."`
![Screenshot 2025-04-28 185916](https://github.com/user-attachments/assets/320d1fe5-6eb0-434c-95a5-08af6bb0f893)
