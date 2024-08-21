import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './Subscribers.css';

function Subscribers() {
    const navigate = useNavigate();
    const [isSubscribed, setIsSubscribed] = useState(false);
    const [videosPosted, setVideosPosted] = useState(false);
    const [isImagessub, setIsImages] = useState(false);


    useEffect(() => {
        const subscribed = localStorage.getItem("subscribed") === "true";
        setIsSubscribed(subscribed);
    }, []);
    useEffect(() => {
        const subscribed2 = localStorage.getItem("subscribed2") === "true";
        setVideosPosted(subscribed2);
    }, []);
    useEffect(() => {
        const subscribed3 = localStorage.getItem("subscribed3") === "true";
        setIsImages(subscribed3);
    }, []);
    
    

    const handleBackClick = () => {
        navigate('/home');
    };

    return (
        <div className="subscribers-container">
            <button className="back1" onClick={handleBackClick}>
                ←
            </button>
            <h1>Subscribers</h1>
            {isSubscribed ? (
                <p>You are <strong style={{ color: 'green' }}>subscribed</strong> to <strong style={{ color: 'green' }}>posts</strong> updates!</p>
            ) : (
                <p>You are not subscribed yet.</p>
            )}
            {videosPosted && (
                <p>You are <strong style={{ color: 'green' }}>subscribed</strong> to <strong style={{ color: 'green' }}>Videos</strong> updates!</p>
            )}
             {isImagessub && (
                <p>You are <strong style={{ color: 'green' }}>subscribed</strong> to <strong style={{ color: 'green' }}>Images</strong> updates!</p>
            )}
        </div>
    );
}

export default Subscribers;
