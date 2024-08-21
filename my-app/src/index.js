// import React from 'react';
// import ReactDOM from 'react-dom/client'; // Updated import
import '@fortawesome/fontawesome-free/css/all.min.css'; // Import FontAwesome CSS
// import App from './App';

// // Create a root element
// const root = ReactDOM.createRoot(document.getElementById('root'));

// // Render your App component
// root.render(
//   <React.StrictMode>
//     <App />
//   </React.StrictMode>
// );
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
// src/index.js or src/index.css
import '@fortawesome/fontawesome-free/css/all.min.css';
// src/index.js or src/index.css
import 'bootstrap-icons/font/bootstrap-icons.css';
import { UserProvider } from './UserContext';



const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

