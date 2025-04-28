import React, { useEffect, useState, useRef, useCallback } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import io from 'socket.io-client';
import { debounce } from 'lodash';
import './TeamSyncStyles.css';

const API_URL = process.env.REACT_APP_API_URL || 'https://team-sync-2.onrender.com';

const Dashboard = () => {
  const [user, setUser] = useState(null);
  const [activeSection, setActiveSection] = useState('dashboard');
  const [allUsers, setAllUsers] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [conversations, setConversations] = useState([]);
  const [loadingConversations, setLoadingConversations] = useState(false);
  const [activeChatUser, setActiveChatUser] = useState(null);
  const [messages, setMessages] = useState([]);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [newMessage, setNewMessage] = useState('');
  const [unreadCounts, setUnreadCounts] = useState({});
  const [totalUnreadCount, setTotalUnreadCount] = useState(0);
  const [socket, setSocket] = useState(null);
  const [isTyping, setIsTyping] = useState(false);
  const [sending, setSending] = useState(false);

  const messagesEndRef = useRef(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchUser = async () => {
      const token = localStorage.getItem('token');
      if (!token) {
        alert('Please login first!');
        navigate('/');
        return;
      }

      try {
        const response = await axios.get(`${API_URL}/api/dashboard`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        setUser(response.data.user);
        console.log('Fetched user:', response.data.user);
      } catch (error) {
        console.error('Error fetching user:', error);
        alert('Session expired. Please login again.');
        localStorage.removeItem('token');
        navigate('/');
      }
    };

    fetchUser();
  }, [navigate]);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token || !user) return;

    const newSocket = io(API_URL, {
      auth: { token },
    });

    newSocket.on('connect', () => {
      console.log('Connected to Socket.io server');
    });

    newSocket.on('connect_error', (err) => {
      console.error('Socket connection error:', err.message);
      alert('Failed to connect to chat server.');
    });

    newSocket.on('messageReceived', (message) => {
      console.log('Message received:', message);
      if (activeChatUser && message.sender === activeChatUser._id) {
        setMessages((prev) => [...prev, message]);
        markMessageAsRead(message._id);
      } else {
        setUnreadCounts((prev) => ({
          ...prev,
          [message.sender]: (prev[message.sender] || 0) + 1,
        }));
        setTotalUnreadCount((prev) => prev + 1);
      }
      fetchConversations();
    });

    newSocket.on('messageSent', (message) => {
      console.log('Message sent event received:', message);
      console.log('Active chat user ID:', activeChatUser?._id);
      console.log('Message receiver ID:', message.receiver);
      if (String(message.sender) === String(user._id)) {
        setMessages((prev) => [...prev, message]);
      }
      setSending(false);
    });

    newSocket.on('messageError', (error) => {
      console.error('Message error:', error);
      alert('Failed to send message. Please try again.');
      setSending(false);
    });

    newSocket.on('userStatusChanged', (data) => {
      setAllUsers((prev) =>
        prev.map((u) =>
          u._id === data.userId
            ? { ...u, status: data.status, statusUpdatedAt: data.statusUpdatedAt }
            : u
        )
      );
      setConversations((prev) =>
        prev.map((u) =>
          u._id === data.userId
            ? { ...u, status: data.status, statusUpdatedAt: data.statusUpdatedAt }
            : u
        )
      );
      if (activeChatUser && activeChatUser._id === data.userId) {
        setActiveChatUser((prev) => ({
          ...prev,
          status: data.status,
          statusUpdatedAt: data.statusUpdatedAt,
        }));
      }
    });

    newSocket.on('userTyping', (data) => {
      if (activeChatUser && data.userId === activeChatUser._id) {
        setIsTyping(true);
        setTimeout(() => setIsTyping(false), 3000);
      }
    });

    newSocket.on('disconnect', () => {
      console.log('Socket disconnected, attempting to reconnect...');
      newSocket.connect();
    });

    setSocket(newSocket);

    return () => {
      newSocket.disconnect();
    };
  }, [user]);

  const fetchUsers = async () => {
    const token = localStorage.getItem('token');
    if (!token) return;

    setLoadingUsers(true);
    try {
      const response = await axios.get(`${API_URL}/api/users`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      console.log('Fetched users:', response.data);
      const validUsers = response.data.filter((u) => u.name && typeof u.name === 'string');
      setAllUsers(validUsers);
    } catch (error) {
      console.error('Error fetching users:', error);
      alert('Failed to load users.');
    } finally {
      setLoadingUsers(false);
    }
  };

  const fetchConversations = async () => {
    const token = localStorage.getItem('token');
    if (!token) return;

    setLoadingConversations(true);
    try {
      const response = await axios.get(`${API_URL}/api/messages/conversations`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const validConversations = response.data.filter((u) => u.name && typeof u.name === 'string');
      setConversations(validConversations);
    } catch (error) {
      console.error('Error fetching conversations:', error);
      alert('Failed to load conversations.');
    } finally {
      setLoadingConversations(false);
    }
  };

  const fetchMessages = async (userId) => {
    const token = localStorage.getItem('token');
    if (!token || !userId) return;

    setLoadingMessages(true);
    try {
      const response = await axios.get(`${API_URL}/api/messages/${userId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      console.log('Fetched messages:', response.data);
      setMessages(response.data);
      fetchUnreadCounts();
      scrollToBottom();
    } catch (error) {
      console.error('Error fetching messages:', error);
      alert('Failed to load messages.');
    } finally {
      setLoadingMessages(false);
    }
  };

  const fetchUnreadCounts = async () => {
    const token = localStorage.getItem('token');
    if (!token) return;

    try {
      const totalResponse = await axios.get(`${API_URL}/api/messages/unread/count`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setTotalUnreadCount(totalResponse.data.count);

      const countsByUserResponse = await axios.get(`${API_URL}/api/messages/unread/counts-by-sender`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setUnreadCounts(countsByUserResponse.data);
    } catch (error) {
      console.error('Error fetching unread counts:', error);
    }
  };

  const markMessageAsRead = async (messageId) => {
    const token = localStorage.getItem('token');
    if (!token) return;

    try {
      await axios.put(
        `${API_URL}/api/messages/${messageId}/read`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setUnreadCounts((prev) => {
        const newCounts = { ...prev };
        if (activeChatUser && newCounts[activeChatUser._id]) {
          newCounts[activeChatUser._id] = Math.max(0, newCounts[activeChatUser._id] - 1);
          setTotalUnreadCount((prev) => Math.max(0, prev - 1));
        }
        return newCounts;
      });
    } catch (error) {
      console.error('Error marking message as read:', error);
    }
  };

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  useEffect(() => {
    if (user) {
      fetchUsers();
      fetchConversations();
      fetchUnreadCounts();
    }
  }, [user]);

  useEffect(() => {
    scrollToBottom();
  }, [messages, scrollToBottom]);

  useEffect(() => {
    if (activeChatUser) {
      fetchMessages(activeChatUser._id);
    }
  }, [activeChatUser]);

  const handlePunchInOut = async () => {
    if (updating || !user) return;

    const token = localStorage.getItem('token');
    if (!token) return;

    setUpdating(true);
    try {
      const newStatus = user.status === 'online' ? 'offline' : 'online';
      await axios.post(
        `${API_URL}/api/users/status`,
        { status: newStatus },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setUser({ ...user, status: newStatus });
      fetchUsers();
    } catch (error) {
      console.error('Error updating status:', error);
      alert('Failed to update status.');
    } finally {
      setUpdating(false);
    }
  };

  const startChat = useCallback((selectedUser) => {
    setActiveChatUser(selectedUser);
    setActiveSection('chat');
  }, []);

  const sendMessage = useCallback(
    (e) => {
      e.preventDefault();
      if (!newMessage.trim() || !activeChatUser || !socket || sending) return;

      console.log('Sending message:', { receiverId: activeChatUser._id, content: newMessage });
      setSending(true);
      socket.emit('sendMessage', {
        receiverId: activeChatUser._id,
        content: newMessage,
      });
      setNewMessage('');
    },
    [newMessage, activeChatUser, socket, sending]
  );

  const emitTyping = useCallback(
    debounce(() => {
      if (!socket || !activeChatUser) return;
      socket.emit('typing', { receiverId: activeChatUser._id });
    }, 500),
    [socket, activeChatUser]
  );

  const handleTyping = useCallback((e) => {
    setNewMessage(e.target.value);
    emitTyping();
  }, [emitTyping]);

  const handleLogout = useCallback(() => {
    if (socket) socket.disconnect();
    localStorage.removeItem('token');
    navigate('/');
  }, [socket, navigate]);

  const formatTime = (timestamp) => {
    return new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const formatDate = (timestamp) => {
    const date = new Date(timestamp);
    const today = new Date();
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);

    if (date.toDateString() === today.toDateString()) return 'Today';
    if (date.toDateString() === yesterday.toDateString()) return 'Yesterday';
    return date.toLocaleDateString();
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'online':
        return '#4CAF50';
      case 'offline':
        return '#F44336';
      default:
        return '#9E9E9E';
    }
  };

  const getTimeAgo = (timestamp) => {
    if (!timestamp) return '';
    const now = new Date();
    const statusTime = new Date(timestamp);
    const diff = Math.floor((now - statusTime) / 1000);

    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  };

  const SidebarItem = ({ icon, label, active, onClick, badge }) => (
    <button
      className={`sidebar-item ${active ? 'sidebar-item-active' : ''}`}
      onClick={onClick}
      aria-label={label}
      role="menuitem"
    >
      <span className="sidebar-icon">{icon}</span>
      <span className="sidebar-label">{label}</span>
      {badge > 0 && (
        <span className="sidebar-badge" aria-label={`${badge} unread messages`}>
          {badge}
        </span>
      )}
    </button>
  );

  if (!user) {
    return <div>Loading...</div>;
  }

  return (
    <div className="dashboard-layout">
      <div className="dashboard-sidebar">
        <div className="sidebar-header">
          <div className="logo">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
              <circle cx="12" cy="12" r="10" stroke="#4A4AE0" strokeWidth="2" />
              <path d="M8 14C8 14 9.5 16 12 16C14.5 16 16 14 16 14" stroke="#4A4AE0" strokeWidth="2" />
              <path d="M9 9H9.01" stroke="#4A4AE0" strokeWidth="2" />
              <path d="M15 9H15.01" stroke="#4A4AE0" strokeWidth="2" />
            </svg>
            <h3>TeamSync</h3>
          </div>
        </div>

        <div className="sidebar-menu">
          <SidebarItem
            icon="📊"
            label="Dashboard"
            active={activeSection === 'dashboard'}
            onClick={() => setActiveSection('dashboard')}
          />
          <SidebarItem
            icon="💬"
            label="Chat"
            active={activeSection === 'chat'}
            onClick={() => setActiveSection('chat')}
            badge={totalUnreadCount}
          />
          <SidebarItem
            icon="👥"
            label="Teams"
            active={activeSection === 'teams'}
            onClick={() => setActiveSection('teams')}
          />
          <SidebarItem
            icon="📅"
            label="Events"
            active={activeSection === 'events'}
            onClick={() => setActiveSection('events')}
          />
          <SidebarItem
            icon="✓"
            label="Tasks"
            active={activeSection === 'tasks'}
            onClick={() => setActiveSection('tasks')}
          />
          <SidebarItem
            icon="📁"
            label="Projects"
            active={activeSection === 'projects'}
            onClick={() => setActiveSection('projects')}
          />
        </div>

        <div className="sidebar-footer">
          <button className="logout-button" onClick={handleLogout}>
            Logout
          </button>
        </div>
      </div>

      <div className="dashboard-content">
        <div className="dashboard-header">
          <h1>
            {activeSection === 'chat' && activeChatUser
              ? `Chat with ${activeChatUser.name || 'Unknown User'}`
              : `Welcome back, ${user.name || 'User'}!`}
          </h1>
          <div className="user-profile">
            <div
              className="avatar"
              style={{ border: user.status ? `2px solid ${getStatusColor(user.status)}` : 'none' }}
            >
              {user.name ? user.name.charAt(0).toUpperCase() : 'U'}
            </div>
          </div>
        </div>

        <div className="dashboard-body">
          {activeSection === 'dashboard' && (
            <div className="dashboard-overview">
              <div className="card">
                <h3>User Information</h3>
                <div className="user-details">
                  <p>
                    <strong>Name:</strong> {user.name || 'N/A'}
                  </p>
                  <p>
                    <strong>Email:</strong> {user.email || 'N/A'}
                  </p>
                  <p>
                    <strong>Joined:</strong>{' '}
                    {user.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'N/A'}
                  </p>
                  <p>
                    <strong>Status:</strong>
                    <span
                      className="status-indicator"
                      style={{
                        backgroundColor: getStatusColor(user.status),
                        display: 'inline-block',
                        width: '10px',
                        height: '10px',
                        borderRadius: '50%',
                        marginLeft: '5px',
                      }}
                    />
                    <span style={{ marginLeft: '5px' }}>
                      {user.status === 'online' ? 'Online' : 'Offline'}
                      {user.statusUpdatedAt && ` (${getTimeAgo(user.statusUpdatedAt)})`}
                    </span>
                  </p>
                  <div className="punch-controls">
                    <button
                      className={`punch-button ${user.status === 'online' ? 'punch-out' : 'punch-in'}`}
                      onClick={handlePunchInOut}
                      disabled={updating}
                    >
                      {updating ? 'Updating...' : user.status === 'online' ? 'Punch Out' : 'Punch In'}
                    </button>
                  </div>
                </div>
              </div>

              <div className="cards-row">
                <div className="card">
                  <h3>Your Teams</h3>
                  <p>No teams yet</p>
                  <button className="secondary-button">Create Team</button>
                </div>
                <div className="card">
                  <h3>Upcoming Events</h3>
                  <p>No upcoming events</p>
                  <button className="secondary-button">Schedule Event</button>
                </div>
              </div>

              <div className="card">
                <h3>All Users ({allUsers.length})</h3>
                {loadingUsers ? (
                  <p>Loading users...</p>
                ) : (
                  <div className="users-list">
                    {allUsers.map((u) => (
                      <div key={u._id} className="user-item">
                        <div
                          className="user-avatar"
                          style={{ border: `2px solid ${getStatusColor(u.status)}` }}
                        >
                          {u.name ? u.name.charAt(0).toUpperCase() : 'U'}
                        </div>
                        <div className="user-info">
                          <p className="user-name">{u.name || 'Unknown User'}</p>
                          <p className="user-status">
                            {u.status === 'online' ? 'Online' : 'Offline'} (
                            {getTimeAgo(u.statusUpdatedAt)})
                          </p>
                        </div>
                        <button
                          className="chat-button"
                          onClick={() => startChat(u)}
                          aria-label={`Start chat with ${u.name || 'Unknown User'}`}
                        >
                          Chat
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {activeSection === 'chat' && (
            <div className="chat-section">
              <div className="chat-users">
                {loadingConversations ? (
                  <p>Loading conversations...</p>
                ) : (
                  conversations.map((convUser) => (
                    <div
                      key={convUser._id}
                      className="chat-user"
                      onClick={() => startChat(convUser)}
                      role="button"
                      tabIndex={0}
                      onKeyPress={(e) => e.key === 'Enter' && startChat(convUser)}
                    >
                      <span className="user-name">{convUser.name || 'Unknown User'}</span>
                      <span
                        className="user-status"
                        style={{ backgroundColor: getStatusColor(convUser.status) }}
                      />
                      <span className="last-seen">{getTimeAgo(convUser.statusUpdatedAt)}</span>
                      {unreadCounts[convUser._id] > 0 && (
                        <span className="unread-badge">{unreadCounts[convUser._id]}</span>
                      )}
                    </div>
                  ))
                )}
              </div>

              {activeChatUser && (
                <div className="chat-box">
                  <h3>Chat with {activeChatUser.name || 'Unknown User'}</h3>
                  {loadingMessages ? (
                    <p>Loading messages...</p>
                  ) : (
                    <div className="messages">
                      {Object.entries(
                        messages.reduce((acc, msg) => {
                          const date = formatDate(msg.timestamp || msg.createdAt);
                          if (!acc[date]) acc[date] = [];
                          acc[date].push(msg);
                          return acc;
                        }, {})
                      ).map(([date, msgs]) => (
                        <div key={date}>
                          <div className="date-divider">{date}</div>
                          {msgs.map((message, index) => (
                            <div
                              key={message._id}
                              className={`message ${
                                String(message.sender) === String(user._id) ? 'sent' : 'received'
                              }`}
                            >
                              <p>{message.content}</p>
                              {index === msgs.length - 1 && (
                                <span>{formatTime(message.timestamp || message.createdAt)}</span>
                              )}
                              {console.log(
                                `Message: ${message.content}, Sender: ${message.sender}, Receiver: ${message.receiver}, User ID: ${user._id}, Class: ${
                                  String(message.sender) === String(user._id) ? 'sent' : 'received'
                                }`
                              )}
                            </div>
                          ))}
                        </div>
                      ))}
                      <div ref={messagesEndRef} />
                    </div>
                  )}

                  {isTyping && (
                    <div className="typing-indicator">
                      {activeChatUser.name || 'Unknown User'} is typing...
                    </div>
                  )}

                  <form onSubmit={sendMessage} className="message-input">
                    <input
                      type="text"
                      value={newMessage}
                      onChange={handleTyping}
                      placeholder="Type a message..."
                      aria-label="Type a message"
                      disabled={sending}
                    />
                    <button type="submit" disabled={!newMessage.trim() || sending}>
                      {sending ? 'Sending...' : 'Send'}
                    </button>
                  </form>
                </div>
              )}
            </div>
          )}

          {activeSection === 'teams' && (
            <div className="teams-section">
              <h2>Teams</h2>
              <p>No teams yet.</p>
            </div>
          )}

          {activeSection === 'events' && (
            <div className="events-section">
              <h2>Events</h2>
              <p>No upcoming events.</p>
            </div>
          )}

          {activeSection === 'tasks' && (
            <div className="tasks-section">
              <h2>Tasks</h2>
              <p>No tasks assigned.</p>
            </div>
          )}

          {activeSection === 'projects' && (
            <div className="projects-section">
              <h2>Projects</h2>
              <p>No projects available.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;