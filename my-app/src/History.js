import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './History.css';

function History() {
    const [timeSpent, setTimeSpent] = useState({
        posts: 0,
        images: 0,
        videos: 0,
        location: 0
    });

    const navigate = useNavigate();

    useEffect(() => {
        const postsTime = Math.floor(Number(localStorage.getItem('postsTime')) || 0);
        const imagesTime = Math.floor(Number(localStorage.getItem('imagesTime')) || 0);
        const videosTime = Math.floor(Number(localStorage.getItem('videosTime')) || 0);
        const locationTime = Math.floor(Number(localStorage.getItem('locationTime')) || 0);

        setTimeSpent({
            posts: postsTime,
            images: imagesTime,
            videos: videosTime,
            location: locationTime
        });
    }, []);

    const handleBackClick = () => {
        // Reset the time tracking in localStorage
        localStorage.setItem('postsTime', '0');
        localStorage.setItem('imagesTime', '0');
        localStorage.setItem('videosTime', '0');
        localStorage.setItem('locationTime', '0');
        
        navigate('/home'); // Navigate to the Home component
    };

    return (
        <div className="history-container">
            <button className="back-button22" onClick={handleBackClick}>&larr; Back</button>
            <h1>Time Spent on Sections</h1>
            <ul>
                <li><strong style={{color: 'black'}}>Posts:</strong> {timeSpent.posts} seconds</li>
                <li><strong style={{color: 'black'}}>Images:</strong> {timeSpent.images} seconds</li>
                <li><strong style={{color: 'black'}}>Videos:</strong> {timeSpent.videos} seconds</li>
                <li><strong style={{color: 'black'}}>Location:</strong> {timeSpent.location} seconds</li>
            </ul>
        </div>
    );
}

export default History;
