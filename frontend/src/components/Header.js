import React from 'react';
import { Link } from 'react-router-dom';

const Header = ({ isAuthenticated, logout }) => {
  return (
    <header>
      <h1>GamePlan</h1>
      <nav>
        <ul>
          <li><Link to="/">Home</Link></li>
          {isAuthenticated ? (
            <>
              <li><Link to="/create-event">Create Event</Link></li>
              <li><button onClick={logout}>Logout</button></li>
            </>
          ) : (
            <>
              <li><Link to="/login">Login</Link></li>
              <li><Link to="/register">Register</Link></li>
            </>
          )}
        </ul>
      </nav>
    </header>
  );
};

export default Header;
