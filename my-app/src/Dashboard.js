import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Loading from './Loading';

function Dashboard() {
  const [showLoading, setShowLoading] = useState(false);
  const [username, setUsername] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    // Retrieve the logged-in user's information from localStorage
    const loggedInUser = JSON.parse(localStorage.getItem('loggedInUser'));

    // Set the username state with the logged-in user's username
    if (loggedInUser) {
      setUsername(loggedInUser.username);
    }

    // Set a timer to show the loading spinner after 3 seconds and then redirect
    const timer = setTimeout(() => {
      setShowLoading(true);
      setTimeout(() => {
        navigate('/home');
      }, 3000);
    }, 3000);

    return () => clearTimeout(timer);
  }, [navigate]);

  return (
    <div className="dashboard-container">
      {!showLoading ? (
        <h1>Welcome, {username}!</h1> // Display the welcome message with the username
      ) : (
        <Loading />
      )}
    </div>
  );
}

export default Dashboard;
