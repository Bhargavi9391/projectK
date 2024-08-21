import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './Images.css';

function Images() {
    const navigate = useNavigate();
    const [view, setView] = useState('grid');

    // Image URLs
    const imagePaths = [
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
    ];

    // Repeat the images to get 20 posts
    const repeatedImages = Array(2).fill(imagePaths).flat().slice(0, 20);

    // State to keep track of likes, dislikes, comments, etc.
    const [imageData, setImageData] = useState(
        repeatedImages.map((url) => ({
            url,
            likes: 0,
            dislikes: 0,
            isLiked: false,
            isDisliked: false,
            comments: [],
            showCommentBox: false,
            newComment: ''
        }))
    );

    // Handle like button click
    const handleLike = (index) => {
        setImageData((prevData) =>
            prevData.map((image, i) =>
                i === index
                    ? {
                          ...image,
                          likes: image.isLiked ? image.likes - 1 : image.likes + 1,
                          isLiked: !image.isLiked,
                          isDisliked: false,
                          dislikes: image.isDisliked ? image.dislikes - 1 : image.dislikes
                      }
                    : image
            )
        );
    };

    // Handle dislike button click
    const handleDislike = (index) => {
        setImageData((prevData) =>
            prevData.map((image, i) =>
                i === index
                    ? {
                          ...image,
                          dislikes: image.isDisliked ? image.dislikes - 1 : image.dislikes + 1,
                          isDisliked: !image.isDisliked,
                          isLiked: false,
                          likes: image.isLiked ? image.likes - 1 : image.likes
                      }
                    : image
            )
        );
    };

    // Toggle the comment box
    const toggleCommentBox = (index) => {
        setImageData((prevData) =>
            prevData.map((image, i) =>
                i === index
                    ? {
                          ...image,
                          showCommentBox: !image.showCommentBox
                      }
                    : image
            )
        );
    };

    // Handle comment input change
    const handleCommentChange = (index, event) => {
        const { value } = event.target;
        setImageData((prevData) =>
            prevData.map((image, i) =>
                i === index
                    ? {
                          ...image,
                          newComment: value
                      }
                    : image
            )
        );
    };

    // Add a comment to the list
    const handleAddComment = (index) => {
        setImageData((prevData) =>
            prevData.map((image, i) =>
                i === index
                    ? {
                          ...image,
                          comments: [...image.comments, image.newComment],
                          newComment: '',
                          showCommentBox: false
                      }
                    : image
            )
        );
    };

    // Delete a comment
    const handleDeleteComment = (imageIndex, commentIndex) => {
        setImageData((prevData) =>
            prevData.map((image, i) =>
                i === imageIndex
                    ? {
                          ...image,
                          comments: image.comments.filter((_, cIndex) => cIndex !== commentIndex)
                      }
                    : image
            )
        );
    };

    // Close the comment box
    const closeCommentBox = (index) => {
        setImageData((prevData) =>
            prevData.map((image, i) =>
                i === index
                    ? {
                          ...image,
                          showCommentBox: false
                      }
                    : image
            )
        );
    };

    // Handle save image to PC
    const handleSaveImage = (url) => {
        const link = document.createElement('a');
        link.href = url;
        link.download = url.substring(url.lastIndexOf('/') + 1);
        link.click();
    };

    // Handle delete image
    const handleDeleteImage = (index) => {
        setImageData((prevData) => prevData.filter((_, i) => i !== index));
    };

    // Show the top liked images or a message if none
    const showTopImages = () => {
        const topImages = imageData
            .filter((image) => image.likes > 0)
            .sort((a, b) => b.likes - a.likes)
            .slice(0, 5); // Show top 5 liked images for example

        return topImages.length > 0 ? (
            <div className="top-images">
                <div className="top-images-header">
                    <h1>This is the Trending Image</h1>
                    <button
                        className="back-button"
                        onClick={() => setView('grid')} // Go back to grid view
                    >
                        &larr; Back
                    </button>
                </div>
                {topImages.map((image, index) => (
                    <div key={index} className="top-image">
                        <img src={image.url} alt={`Trending Image ${index + 1}`} />
                    </div>
                ))}
            </div>
        ) : (
            <div className="no-images-message">
                <button
                    className="back-button"
                    onClick={() => setView('grid')} // Go back to grid view
                >
                    &larr; Back
                </button>
                <h1>No trending images. Like some images to see trending ones.</h1>
            </div>
        );
    };
    const handleSubscribe = () => {
        alert("Subscribed!");
        localStorage.setItem("subscribed3", "true");
    };

    const handleUnsubscribe = () => {
        localStorage.removeItem("subscribed3");
        alert("Subscription reset!");
    };

    return (
        <div className="images-container">
            {view === 'grid' && (
                <>
                    <button
                        className="home-button"
                        onClick={() => navigate('/home')} // Navigate to Home.js
                    >
                        <i className="fa fa-home"></i> {/* FontAwesome home icon */}
                    </button>
                    <header className="images-header">
                        <h1>Images</h1>
                        <button className="filter-button" onClick={() => setView('top')}>
                            <i className="fa fa-star"></i> {/* FontAwesome top image icon */}
                        </button>
                        <button className="subscribe-b1" title="Subscribe" onClick={handleSubscribe}>
                    Subscribe
                </button>
                <button className="reset-subscription-button" title="Reset Subscription" onClick={handleUnsubscribe}>
                    Reset Subscription
                </button>   
                    </header>
                    <div className="image-grid">
                        {imageData.map((image, index) => (
                            <div key={index} className="image-item">
                                <img src={image.url} alt={`Image ${index + 1}`} />
                                <div className="image-actions">
                                    <button
                                        className={`like-icon ${image.isLiked ? 'liked' : ''}`}
                                        onClick={() => handleLike(index)}
                                    >
                                        ❤️ {image.likes}
                                    </button>
                                    <button
                                        className={`dislike-icon ${image.isDisliked ? 'disliked' : ''}`}
                                        onClick={() => handleDislike(index)}
                                    >
                                        👎 {image.dislikes}
                                    </button>
                                    <button
                                        className="comment-icon"
                                        onClick={() => toggleCommentBox(index)}
                                    >
                                        💬
                                    </button>
                                    <button
                                        className="save-icon"
                                        onClick={() => handleSaveImage(image.url)}
                                    >
                                        💾
                                    </button>
                                    <button
                                        className="delete-icon"
                                        onClick={() => handleDeleteImage(index)}
                                    >
                                        🗑️ 
                                    </button>
                                    
                                </div>
                                {image.showCommentBox && (
                                    <div className="comment-box active">
                                        <button className="close-btn" onClick={() => closeCommentBox(index)}>×</button>
                                        <textarea
                                            value={image.newComment}
                                            onChange={(e) => handleCommentChange(index, e)}
                                            placeholder="Add a comment..."
                                        />
                                        <button onClick={() => handleAddComment(index)}>Submit</button>
                                        <div className="comment-list">
                                            {image.comments.map((comment, i) => (
                                                <p key={i}>
                                                    {comment}
                                                    <button 
                                                        className="delete-btn"
                                                        onClick={() => handleDeleteComment(index, i)}
                                                    >
                                                        ×
                                                    </button>
                                                </p>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                </>
            )}
            {view === 'top' && showTopImages()}
        </div>
    );
}

export default Images;
