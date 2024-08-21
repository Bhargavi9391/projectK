import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './Login.css';

const Login = () => {
    const [formData, setFormData] = useState({
        username: '',
        password: ''
    });
    const [message, setMessage] = useState('');
    const navigate = useNavigate();

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData({
            ...formData,
            [name]: value
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const response = await fetch('http://localhost:5001/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            });
            const data = await response.json();
            if (response.ok) {
                setMessage('Login successful!');
                // Save user details to localStorage
                localStorage.setItem('loggedInUser', JSON.stringify(data.user));
                navigate('/dashboard');
            } else {
                setMessage(data.message || 'Invalid username or password.');
            }
        } catch (error) {
            setMessage('Login failed. Please try again later.');
            console.error('Error:', error);
        }
    };

    return (
        <div className="stars-container">
            {[...Array(80)].map((_, index) => (
                <div key={index} className="mini-star"></div>
            ))}
            <div className="rotating-message">
                <span>S</span>
                <span>t</span>
                <span>a</span>
                <span>r</span>
                <span>T</span>
                <span>a</span>
                <span>l</span>
                <span>k</span>
            </div>
            <div className="login-container">
                <h2>Login</h2>
                <form onSubmit={handleSubmit}>
                    <div>
                        <label>
                            Username:<br />
                            <input
                                type="text"
                                name="username"
                                value={formData.username}
                                onChange={handleChange}
                            />
                        </label>
                    </div>
                    <div>
                        <label>
                            Password:<br />
                            <input
                                type="password"
                                name="password"
                                value={formData.password}
                                onChange={handleChange}
                            />
                        </label>
                    </div>
                    <button type="submit">Login</button>
                </form>
                <div style={{ marginTop: '10px', textAlign: 'center' }}>
                    <a href="/register">Register Now</a>
                </div>
                {message && <p className="message">{message}</p>}
            </div>
        </div>
    );
};

export default Login;
