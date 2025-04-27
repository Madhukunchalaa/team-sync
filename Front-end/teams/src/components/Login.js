import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios'; // ✅ Import axios

function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    try {
      // 👇 Replace with your actual backend login endpoint
      const response = await axios.post('http://localhost:5000/api/auth/login', {
        email,
        password,
      });

      // Example: save token to localStorage (if backend returns a token)
      localStorage.setItem('token', response.data.token);

      console.log('Login successful:', response.data);
      alert('Login successful!');
      navigate('/dashboard');
    } catch (error) {
      console.error('Login error:', error.response?.data || error.message);
      alert('Login failed! ' + (error.response?.data?.message || 'Check credentials.'));
    }
  };

  return (
    <div className="login-container">
      <header className="login-header">
        <div className="logo">
          <svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor">
            <circle cx="12" cy="12" r="10" fillOpacity="0.2" />
            <circle cx="12" cy="12" r="4" />
          </svg>
          <h1>TeamSync</h1>
        </div>
      </header>
      
      <main className="login-content">
        <h2>Log in to TeamSync</h2>
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="email">Email</label>
            <input
              type="email"
              id="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              placeholder="Enter your password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          
          <div className="remember-me">
            <input
              type="checkbox"
              id="remember"
              checked={rememberMe}
              onChange={(e) => setRememberMe(e.target.checked)}
            />
            <label htmlFor="remember">Remember me</label>
          </div>
          
          <button type="submit" className="login-button">Log in</button>
        </form>

        <div className="forgot-password">
          <Link to="/forgot-password">Forgot password?</Link>
        </div>
        
        <div className="signup">
          <span>Don't have an account? </span>
          <Link to="/signup">Sign up</Link>
        </div>
      </main>
    </div>
  );
}

export default Login;
