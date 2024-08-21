// src/App.js
import React from 'react';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import Login from './Login';
import StarIcon from './StarIcon';
import Register from './Register';
import Dashboard from './Dashboard';
import Home from './Home'; // Import the Home component
import Loading from './Loading'; // Import the Loading component
import Posts from './Posts'; // Import the Post component
import Images from './Images';
import Videos from './Videos';
import Location from './Location';
import Reviews from './Reviews';
import Subscribers from './Subscribers';
import History from './History';
import Message from './Message';

// Define routes using createBrowserRouter
const router = createBrowserRouter([
  {
    path: '/',
    element: <StarIcon />, // Set StarIcon as the default component
  },
  {
    path: '/login',
    element: <Login />,
  },
  {
    path: '/register',
    element: <Register />,
  },
  {
    path: '/loading',
    element: <Loading />, // Use the Loading component for loading state
  },
  {
    path: '/dashboard',
    element: <Dashboard />,
  },
  {
    path: '/home',
    element: <Home />, // Add the route for Home component
  },
  {
    path: '/posts',
    element: <Posts />, // Correct path for navigating to Post component
  },
  {
    path: '/images',
    element: <Images />, // Correct path for navigating to Post component
  },
  {
    path:'/videos',
    element: <Videos />,
  },
  {
    path: '/location',
    element: <Location />,
  },
  {
    path: '/reviews',
    element: <Reviews />,
  },
  {
    path: '/subscribers',
    element: <Subscribers />,
  },
  {
    path: '/history',
    element: <History />,
  },
  {
    path: '/message',
    element: <Message />,
  }
  
]);

function App() {
  return (
    <RouterProvider router={router} />
  );
}

export default App;
