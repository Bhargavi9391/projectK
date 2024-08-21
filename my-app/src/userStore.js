// src/userStore.js

let users = {};

export const addUser = (username, password) => {
    users[username] = password; // Directly stores the password as plain text
};

export const getUserPassword = (username) => {
    return users[username]; // Returns the stored password directly
};
