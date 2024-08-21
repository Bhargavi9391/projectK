import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './Location.css';

function Location() {
    const [location, setLocation] = useState(null);
    const [error, setError] = useState(null);
    const [timestamp, setTimestamp] = useState(null);
    const [stateCountry, setStateCountry] = useState({ state: '', country: '' });
    const navigate = useNavigate(); // Hook for navigation
    const [startTime, setStartTime] = useState(Date.now());

    useEffect(() => {
        return () => {
            const endTime = Date.now();
            const timeSpent = (endTime - startTime) / 1000; // time in seconds
            const prevTime = Number(localStorage.getItem('locationTime')) || 0;
            localStorage.setItem('locationTime', prevTime + timeSpent);
        };
    }, [startTime]);

    useEffect(() => {
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(
                async (position) => {
                    const { latitude, longitude } = position.coords;
                    const date = new Date();
                    setLocation({ latitude, longitude });
                    setTimestamp(date.toLocaleString());

                    try {
                        const response = await fetch(
                            `https://nominatim.openstreetmap.org/reverse?format=json&lat=${latitude}&lon=${longitude}&zoom=10&addressdetails=1`
                        );
                        const data = await response.json();
                        const state = data.address.state || 'N/A';
                        const country = data.address.country || 'N/A';
                        setStateCountry({ state, country });
                    } catch (error) {
                        setError('Failed to fetch location details.');
                    }
                },
                (err) => setError('Failed to get current position. ' + err.message)
            );
        } else {
            setError('Geolocation is not supported by this browser.');
        }
    }, []);

    return (
        <div className="location-container">
           
            {error ? (
                <div className="error-message" aria-live="assertive">
                    Error: {error}
                </div>
            ) : location ? (
                <div>
                    <h2>Current Location</h2>
                    <p><span style={{ fontWeight: 'bold' }}>Latitude:</span> <span style={{ color: 'black' }}>{location.latitude}</span></p>
                    <p><span style={{ fontWeight: 'bold' }}>Longitude:</span> <span style={{ color: 'black' }}>{location.longitude}</span></p>
                    <p><span style={{ fontWeight: 'bold' }}>Timestamp:</span> <span style={{ color: 'black' }}>{timestamp}</span></p>
                    <p><span style={{ fontWeight: 'bold' }}>State:</span> <span style={{ color: 'black' }}>{stateCountry.state}</span></p>
                    <p><span style={{ fontWeight: 'bold' }}>Country:</span> <span style={{ color: 'black' }}>{stateCountry.country}</span></p>
                </div>
            ) : (
                <div className="loading" aria-live="polite">
                    Loading...
                </div>
            )}
             <button className="back-button3" onClick={() => navigate('/home')}>Back</button>
        </div>
    );
}

export default Location;
