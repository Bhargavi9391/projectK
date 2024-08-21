import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Message from './Message'; // Ensure this component exists
import './Home.css';

function Home() {
    const [showMessage, setShowMessage] = useState(false);
    const [user, setUser] = useState(null);
    const navigate = useNavigate();

    const handleNavigateToPosts = () => {
        navigate('/posts');
    };

    const handleNavigateToImages = () => {
        navigate('/images');
    };

    const handleNavigateToVideos = () => {
        navigate('/videos');
    };

    const handleNavigateToLocation = () => {
        navigate('/location');
    };

    const handleNavigateToSubscribers = () => {
        navigate('/subscribers');
    };

    const handleNavigateToHistory = () => {
        navigate('/history');
    };

    const handleFilterIconClick = () => {
        try {
            const loggedInUser = JSON.parse(localStorage.getItem('loggedInUser'));
            if (loggedInUser) {
                setUser(loggedInUser);
                setShowMessage(true);
            } else {
                console.error("No logged-in user found");
            }
        } catch (error) {
            console.error("Error parsing JSON: ", error);
        }
    };

    const handleCloseMessage = () => {
        setShowMessage(false);
    };

    return (
        <div className="home-container">
            <div className="search-container">
                <div className="input-wrapper">
                    <button className="filters-icon" aria-label="Filters" onClick={handleFilterIconClick}>
                        Profile
                    </button>
                    <input type="text" placeholder="Search..." />
                    <button className="search-icon" aria-label="Search">🔍</button>
                    <button className="microphone-icon" aria-label="Microphone">🎙️</button>
                </div>
            </div>
            <div className="button-row">
                <button className="button-posts" onClick={handleNavigateToPosts}>Posts</button>
                <button className="button-images" onClick={handleNavigateToImages}>Images</button>
                <button className="button-videos" onClick={handleNavigateToVideos}>Videos</button>
            </div>
            <div className="info-row">
                <button className="button-memes" onClick={handleNavigateToLocation}>Location</button>
                <button className="button-history" onClick={handleNavigateToHistory}>History</button>
                <button className="button-subscribers" onClick={handleNavigateToSubscribers}>Subscribers</button>
            </div>
            {showMessage && <Message onClose={handleCloseMessage} user={user} />}
        </div>
    );
}

export default Home;
