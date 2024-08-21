import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './Videos.css';
import { FaTrash, FaSave } from 'react-icons/fa';

function Videos() {
    const navigate = useNavigate();
    const [isSubscribed, setIsSubscribed] = useState(false);
    const [startTime, setStartTime] = useState(Date.now());

    useEffect(() => {
        return () => {
            const endTime = Date.now();
            const timeSpent = (endTime - startTime) / 1000; // time in seconds
            const prevTime = Number(localStorage.getItem('videosTime')) || 0;
            localStorage.setItem('videosTime', prevTime + timeSpent);
        };
    }, [startTime]);

    useEffect(() => {
        const subscribed = localStorage.getItem("subscribed") === "true";
        setIsSubscribed(subscribed);
    }, []);

    const handleSubscribe = () => {
        setIsSubscribed(true);
        localStorage.setItem("subscribed2", "true");
        alert("Subscribed!");  // Alert when subscribed
    };

    const handleUnsubscribe = () => {
        setIsSubscribed(false);
        localStorage.setItem("subscribed2", "false");
        alert("Unsubscribed!");  // Alert when unsubscribed
    };

    const handleNavigateBack = () => {
        navigate('/home');
    };

    const [videoSources, setVideoSources] = useState([
        '/movie1.mp4', '/movie2.mp4', '/movie1.mp4',
        '/movie1.mp4', '/movie2.mp4', '/movie1.mp4',
        '/movie1.mp4', '/movie2.mp4', '/movie1.mp4',
        '/movie2.mp4', '/movie1.mp4', '/movie1.mp4',
        '/movie1.mp4', '/movie2.mp4', '/movie1.mp4',
        '/movie1.mp4', '/movie2.mp4', '/movie1.mp4',
    ]);

    const [videoStates, setVideoStates] = useState(
        videoSources.map(() => ({
            likes: 0,
            dislikes: 0,
        }))
    );

    const handleLike = (index) => {
        setVideoStates(prevStates => {
            const updatedStates = [...prevStates];
            updatedStates[index].likes += 1;
            return updatedStates;
        });
    };

    const handleDislike = (index) => {
        setVideoStates(prevStates => {
            const updatedStates = [...prevStates];
            updatedStates[index].dislikes += 1;
            return updatedStates;
        });
    };

    const handleFileChange = (e) => {
        const file = e.target.files[0];
        if (file) {
            const videoURL = URL.createObjectURL(file);
            setVideoSources(prevSources => [...prevSources, videoURL]);
            setVideoStates(prevStates => [...prevStates, {
                likes: 0,
                dislikes: 0,
            }]);
        }
    };

    const handleDelete = (index) => {
        setVideoSources(prevSources => prevSources.filter((_, i) => i !== index));
        setVideoStates(prevStates => prevStates.filter((_, i) => i !== index));
    };

    const handleSave = (index) => {
        const videoURL = videoSources[index];
        const link = document.createElement('a');
        link.href = videoURL;
        link.download = `video${index + 1}.mp4`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    return (
        <div className="videos-container">
            <div className="header">
                <button className="back-button2" onClick={handleNavigateBack} aria-label="Back">←</button>
                <h1>Videos</h1>
                <input
                    type="file"
                    accept="video/*"
                    onChange={handleFileChange}
                    style={{ display: 'none' }}
                    id="video-upload"
                />
                <label htmlFor="video-upload" className="add-video-button">
                    Add Video
                </label>
                <button className="subscribe-b1" onClick={handleSubscribe}>
                    Subscribe
                </button>
                <button className="reset-subscription-button" onClick={handleUnsubscribe}>
                    Unsubscribe
                </button>
            </div>
            <div className="video-list">
                {videoSources.map((src, index) => (
                    <div className="video-item" key={index}>
                        <video src={src} controls>
                            Your browser does not support the video tag.
                        </video>
                        <div className="video-info">
                            <button className="like-button" onClick={() => handleLike(index)}>❤️ {videoStates[index].likes}</button>
                            <button className="dislike-button" onClick={() => handleDislike(index)}>👎 {videoStates[index].dislikes}</button>
                            <button className="delete-button2" onClick={() => handleDelete(index)}>
                                <FaTrash />
                            </button>
                            <button className="save-button2" onClick={() => handleSave(index)}>
                                <FaSave />
                            </button>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}

export default Videos;
