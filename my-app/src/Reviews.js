import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import './Reviews.css';

function Reviews() {
    const { state } = useLocation();
    const navigate = useNavigate();
    const mediaWithLikes = state?.mediaWithLikes || [];

    const getRating = (likes) => {
        if (likes >= 4) return '★★★★☆'; // 4+ likes
        if (likes === 3) return '★★★☆☆'; // 3 likes
        if (likes === 2) return '★★☆☆☆'; // 2 likes
        if (likes === 1) return '★☆☆☆☆'; // 1 like
        return '☆☆☆☆☆'; // 0 likes
    };

    return (
        <div className="reviews-container">
           
                <button className="back-button" onClick={() => navigate('/posts')}>← Back</button>
               <h2>Media Reviews</h2>
           
            <div className="media-list">
                {mediaWithLikes.map((item, index) => (
                    <div key={index} className="review-item">
                        {item.url.endsWith('.mp4') ? (
                            <video src={item.url} controls className="review-media" />
                        ) : (
                            <img src={item.url} alt={`Media ${index + 1}`} className="review-media" />
                        )}
                        <div className="rating">
                         <bold style={{color:'black'}}>Rating: </bold>   {getRating(item.likes)}
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}

export default Reviews;
