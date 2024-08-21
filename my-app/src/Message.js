import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './Message.css';

function Message({ onClose, user }) {
    const navigate = useNavigate();

    // State to hold the current date and time
    const [currentDateTime, setCurrentDateTime] = useState(new Date().toLocaleString());

    // Update the time every second
    useEffect(() => {
        const interval = setInterval(() => {
            setCurrentDateTime(new Date().toLocaleString());
        }, 1000);

        // Cleanup the interval on component unmount
        return () => clearInterval(interval);
    }, []);

    const handleClose = () => {
        onClose();
        navigate('/'); // Navigate to the root URL
    };

    return (
        <div className="thank-you-message">
            <div className="message-content">
                <p>Thank you for reviewing our app, <strong style={{color:'navy'}}>{user?.username}!!</strong></p>
                <p>Current Date and Time:<span style={{color:'black'}}> {currentDateTime}</span></p> {/* Display current date and time */}
                {user && (
                    <div>
                        <p><span style={{color:'black'}}>Username:</span><bold style={{color:'green'}}> {user.username}</bold></p>
                        <p><span style={{color:'black'}}>Password:</span><bold style={{color:'green'}}>{user.password}</bold></p>
                    </div>
                )}
                <button onClick={handleClose}>Logout</button>

                {/* Balloons */}
                <div className="balloon"></div>
                <div className="balloon"></div>
                <div className="balloon"></div>
                <div className="balloon"></div>
                <div className="balloon"></div>

                {/* Sparkles */}
                <div className="sparkle"></div>
                <div className="sparkle"></div>
                <div className="sparkle"></div>
                <div className="sparkle"></div>
                <div className="sparkle"></div>
            </div>
        </div>
    );
}

export default Message;
