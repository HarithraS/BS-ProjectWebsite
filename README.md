# BS-ProjectWebsite

A full-featured social & chat web application built with Flask, enabling user authentication, friend relationships, real-time chat, friend suggestions, timed file sharing, and more.

## Project Overview  
This project implements a social networking style system where users can:
- Home page shows users whoever uploaded their file with date & time for everyone with "add to friend" button individually
- Sign up, log in, logout (JWT-based authentication)  
- Create and manage friendships (send/accept/reject friend requests)  
- View and manage their friends list  
- Unfriend other users and receive notifications  
- Receive “friend suggestions” based on friends-of-friends mutual connections  
- Chat with friends (basic UI/UX for chat conversations)
- Send any type of file to friends with a selected time-limited and download window
- View, delete and edit their profile 

## Key Features  
- **User Authentication** — Secure login/signup, timeout session flow using JWT tokens  
- **Friend Requests** — Send, accept, reject friend requests  
- **Friends List** — View current friends, unfriend with confirmation  
- **Unfriend Notifications** — Track when someone unfriends you or you unfriend someone  
- **Friend Suggestions** — Algorithm suggests friends-of-friends who you're not already connected with  
- **Timed File Sharing** — Users can upload and send any file type to friends, and recipients can download it only during a selected time limit  
- **Chat Interface** — Basic front-end chat interface for message exchange only with friends
- **Responsive UI** — Simple, clean interface built using HTML, CSS, js and Jinja templates  
