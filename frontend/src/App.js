import React, { useState } from 'react';
import { BrowserRouter as Router, Route, Switch } from 'react-router-dom';
import Header from './components/Header';
import Login from './components/Login';
import Register from './components/Register';
import EventList from './components/EventList';
import EventDetails from './components/EventDetails';
import CreateEvent from './components/CreateEvent';
import './App.css';

const App = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  const logout = () => {
    // Implement logout logic
    setIsAuthenticated(false);
  };

  return (
    <Router>
      <Header isAuthenticated={isAuthenticated} logout={logout} />
      <Switch>
        <Route path="/" exact component={EventList} />
        <Route path="/login">
          <Login setIsAuthenticated={setIsAuthenticated} />
        </Route>
        <Route path="/register">
          <Register setIsAuthenticated={setIsAuthenticated} />
        </Route>
        <Route path="/create-event">
          {isAuthenticated ? <CreateEvent /> : <p>Please login to create an event</p>}
        </Route>
        <Route path="/event/:id">
          <EventDetails isAuthenticated={isAuthenticated} />
        </Route>
      </Switch>
    </Router>
  );
};

export default App;
