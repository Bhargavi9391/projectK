import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './Post.css';

function Posts() {
    const [media, setMedia] = useState([]);
    const [mediaFiles, setMediaFiles] = useState([]);
    const [likeCounts, setLikeCounts] = useState([]);
    const [dislikeCounts, setDislikeCounts] = useState([]);
    const navigate = useNavigate();
    const [startTime, setStartTime] = useState(Date.now());

    useEffect(() => {
        return () => {
            const endTime = Date.now();
            const timeSpent = (endTime - startTime) / 1000; // time in seconds
            const prevTime = Number(localStorage.getItem('postsTime')) || 0;
            localStorage.setItem('postsTime', prevTime + timeSpent);
        };
    }, [startTime]);

    const mediaPaths = [
        '/nature-images/image1.jpg',
        '/nature-images/image2.jpg',
        '/nature-images/image3.jpg',
        '/nature-images/image4.jpg',
        '/nature-images/image5.jpg',
        '/nature-images/image6.jpg',
        '/nature-images/image7.jpg',
        '/nature-images/image8.jpg',
        '/nature-images/image9.jpg',
        '/nature-images/image10.jpg',
        'movie1.mp4',
        'movie2.mp4',
    ];

    const loadPosts = () => {
        let repeatedMedia = [];
        for (let i = 0; i < 50; i++) {
            repeatedMedia = repeatedMedia.concat(mediaPaths);
        }
        const shuffledMedia = repeatedMedia.sort(() => 0.5 - Math.random());
        const selectedMedia = shuffledMedia.slice(0, 100);
        setMedia(selectedMedia);
        setLikeCounts(Array(selectedMedia.length).fill(0));
        setDislikeCounts(Array(selectedMedia.length).fill(0));
    };

    const handleFileChange = (event) => {
        const files = Array.from(event.target.files);
        const fileUrls = files.map(file => URL.createObjectURL(file));
        setMediaFiles(prevFiles => [...prevFiles, ...fileUrls]);
        setLikeCounts(prevCounts => [...prevCounts, ...Array(fileUrls.length).fill(0)]);
        setDislikeCounts(prevCounts => [...prevCounts, ...Array(fileUrls.length).fill(0)]);
    };

    const addFile = () => {
        document.getElementById('file-input').click();
    };

    const handleBack = () => {
        navigate('/home'); // Navigate to home page
    };

    const handleStarClick = () => {
        const combinedMedia = [...media, ...mediaFiles];
        const combinedLikeCounts = [...likeCounts, ...dislikeCounts];

        // Pair media with like counts
        const mediaWithLikes = combinedMedia.map((item, index) => ({
            url: item,
            likes: combinedLikeCounts[index],
        }));

        // Sort by like counts in descending order
        mediaWithLikes.sort((a, b) => b.likes - a.likes);

        // Navigate with sorted media
        navigate('/reviews', {
            state: { mediaWithLikes },
        });
    };

    const handleDelete = (index, fromFile = false) => {
        if (fromFile) {
            const updatedMediaFiles = [...mediaFiles];
            updatedMediaFiles.splice(index, 1);
            setMediaFiles(updatedMediaFiles);

            const updatedLikeCounts = [...likeCounts];
            updatedLikeCounts.splice(media.length + index, 1);
            setLikeCounts(updatedLikeCounts);

            const updatedDislikeCounts = [...dislikeCounts];
            updatedDislikeCounts.splice(media.length + index, 1);
            setDislikeCounts(updatedDislikeCounts);
        } else {
            const updatedMedia = [...media];
            updatedMedia.splice(index, 1);
            setMedia(updatedMedia);

            const updatedLikeCounts = [...likeCounts];
            updatedLikeCounts.splice(index, 1);
            setLikeCounts(updatedLikeCounts);

            const updatedDislikeCounts = [...dislikeCounts];
            updatedDislikeCounts.splice(index, 1);
            setDislikeCounts(updatedDislikeCounts);
        }
    };

    const handleLike = (index) => {
        const updatedLikeCounts = [...likeCounts];
        updatedLikeCounts[index] += 1;
        setLikeCounts(updatedLikeCounts);
    };

    const handleDislike = (index) => {
        const updatedDislikeCounts = [...dislikeCounts];
        updatedDislikeCounts[index] += 1;
        setDislikeCounts(updatedDislikeCounts);
    };

    const handleSubscribe = () => {
        alert("Subscribed!");
        localStorage.setItem("subscribed", "true");
    };

    const handleUnsubscribe = () => {
        localStorage.removeItem("subscribed");
        alert("Subscription reset!");
    };

    return (
        <div className="post-container">
            <button className="back-button1" onClick={handleBack}>← Back</button>
            <div className="button-group">
                <button className="load-posts-button" onClick={loadPosts}>
                    Load Posts
                </button>
                <button className="add-file-button" onClick={addFile}>
                    Add a Post
                </button>
                <button className="star-icon-button" title="Star" onClick={handleStarClick}>
                    ★
                </button>
                <button className="subscribe-b1" title="Subscribe" onClick={handleSubscribe}>
                    Subscribe
                </button>
                <button className="reset-subscription-button" title="Reset Subscription" onClick={handleUnsubscribe}>
                    Reset Subscription
                </button>
            </div>
            <input
                id="file-input"
                type="file"
                accept="image/*,video/*"
                multiple
                style={{ display: 'none' }}
                onChange={handleFileChange}
            />
            <div className="images-container">
                {(media.length > 0 || mediaFiles.length > 0) ? (
                    [...media, ...mediaFiles].map((url, index) => (
                        <div key={index} className="media-wrapper">
                            {url.endsWith('.mp4') ? (
                                <video src={url} controls className="post-media" />
                            ) : (
                                <img src={url} alt={`Post ${index + 1}`} className="post-media" />
                            )}
                            <div className="icon-group">
                                <a href={url} download={`media-${index + 1}`} className="icon-button" title="Save Media">
                                    💾
                                </a>
                                <span
                                    className="icon-button icon-heart"
                                    title="Love Media"
                                    onClick={() => handleLike(index)}
                                >
                                    ❤️ {likeCounts[index]}
                                </span>
                                <span
                                    className="icon-button icon-dislike"
                                    title="Dislike Media"
                                    onClick={() => handleDislike(index)}
                                >
                                    👎 {dislikeCounts[index]}
                                </span>
                                <button className="icon-button" onClick={() => handleDelete(index, mediaFiles.includes(url))} title="Delete Media">
                                    🗑️
                                </button>
                            </div>
                        </div>
                    ))
                ) : (
                    <p className="no-images-message" style={{ color: 'blue' }}>No media loaded. Click <span className="highlight">"Load Posts"</span> or <span className="highlight">"Add a File"</span> to see media.</p>
                )}
            </div>
        </div>
    );
}

export default Posts;
