import React from 'react';
import './StarIcon.css';
import { useNavigate } from 'react-router-dom';

function StarIcon() {
  const navigate = useNavigate(); // Initialize useNavigate

  const handleLoginClick = () => {
    navigate('/login'); // Navigate to the login page
  };

  return (
    <div className="star-container">
      <div className="star">
        <div className="eye left-eye"></div>
        <div className="eye right-eye"></div>
        <div className="smile"></div>
        <div className="shine"></div>
      </div>
      
      {[...Array(80)].map((_, i) => (
        <div key={i} className="mini-star"></div>
      ))}
  
      <div className="star-talk">
        {Array.from("StarTalk").map((letter, index) => (
          <span key={index} className="letter" style={{ '--i': index }}>{letter}</span>
        ))}
      </div>

      {/* Login Button */}
      <button className="login-btn" onClick={handleLoginClick}>Login</button>
    </div>
  );
}

export default StarIcon;
