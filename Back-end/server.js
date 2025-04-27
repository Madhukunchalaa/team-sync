const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const socketIo = require('socket.io');
const dotenv = require('dotenv');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const User = require('./models/User');
const Message = require('./models/Message');
const { registerUser, loginUser, protectedRoute } = require('./controllers/authController');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST'],
  },
});

// Middleware
app.use(cors());
app.use(express.json());

// Authentication Middleware
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('JWT verification failed:', err.message);
    res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch((err) => console.error('❌ MongoDB connection error:', err.message));

// Socket.io Authentication Middleware
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('Authentication token missing'));

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return next(new Error('Authentication error: ' + err.message));
    socket.userId = decoded.id;
    next();
  });
});

// Socket.io Event Handlers
io.on('connection', (socket) => {
  console.log('👤 User connected:', socket.userId);

  // Join user's own room
  socket.join(socket.userId);

  // Update user status to online
  User.findByIdAndUpdate(
    socket.userId,
    { status: 'online', statusUpdatedAt: Date.now() },
    { new: true }
  )
    .then((user) => {
      if (user) {
        io.emit('userStatusChanged', {
          userId: user._id.toString(),
          status: user.status,
          statusUpdatedAt: user.statusUpdatedAt,
        });
      }
    })
    .catch((err) => console.error('Error updating status:', err.message));

  // Handle sending messages
  socket.on('sendMessage', async (data) => {
    try {
      const { receiverId, content } = data;
      console.log('📩 Sending message - Sender:', socket.userId, 'Receiver:', receiverId, 'Content:', content);

      if (socket.userId === receiverId) {
        return socket.emit('messageError', { error: 'Cannot message yourself' });
      }

      const newMessage = new Message({
        sender: socket.userId,
        receiver: receiverId,
        content,
        read: false,
        createdAt: Date.now(),
      });

      await newMessage.save();

      const formattedMessage = {
        ...newMessage.toObject(),
        _id: newMessage._id.toString(),
        sender: newMessage.sender.toString(),
        receiver: newMessage.receiver.toString(),
      };

      socket.emit('messageSent', formattedMessage);
      io.to(receiverId).emit('messageReceived', formattedMessage);
    } catch (err) {
      console.error('❌ Error sending message:', err.message);
      socket.emit('messageError', { error: 'Failed to send message' });
    }
  });

  // Handle typing indicator
  socket.on('typing', (data) => {
    const { receiverId } = data;
    io.to(receiverId).emit('userTyping', { userId: socket.userId });
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    console.log('👤 User disconnected:', socket.userId);

    User.findByIdAndUpdate(
      socket.userId,
      { status: 'offline', statusUpdatedAt: Date.now() },
      { new: true }
    )
      .then((user) => {
        if (user) {
          io.emit('userStatusChanged', {
            userId: user._id.toString(),
            status: user.status,
            statusUpdatedAt: user.statusUpdatedAt,
          });
        }
      })
      .catch((err) => console.error('Error updating disconnect status:', err.message));
  });
});

// Auth Routes
const authRouter = express.Router();
authRouter.post('/register', registerUser);
authRouter.post('/login', loginUser);
authRouter.get('/protected', authMiddleware, protectedRoute);
app.use('/api/auth', authRouter);

// Dashboard Route
app.get('/api/dashboard', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ user: { ...user.toObject(), _id: user._id.toString() } });
  } catch (err) {
    console.error('❌ Dashboard error:', err.message);
    res.status(500).json({ message: 'Server error fetching user' });
  }
});

// Users Routes
app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    const users = await User.find().select('-password -__v');
    res.json(users.map((user) => ({ ...user.toObject(), _id: user._id.toString() })));
  } catch (err) {
    console.error('❌ Error fetching users:', err.message);
    res.status(500).json({ message: 'Server error fetching users' });
  }
});

app.post('/api/users/status', authMiddleware, async (req, res) => {
  try {
    const { status } = req.body;
    if (!['online', 'offline', 'away'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status value' });
    }

    const user = await User.findById(req.user.id);
    user.status = status;
    user.statusUpdatedAt = Date.now();
    await user.save();

    res.json({
      success: true,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        status: user.status,
        statusUpdatedAt: user.statusUpdatedAt,
      },
    });
  } catch (err) {
    console.error('❌ Status update error:', err.message);
    res.status(500).json({ message: 'Server error updating status' });
  }
});

app.get('/api/messages/conversations', authMiddleware, async (req, res) => {
  try {
    const sentMessages = await Message.find({ sender: req.user.id }).distinct('receiver');
    const receivedMessages = await Message.find({ receiver: req.user.id }).distinct('sender');
    const conversationUserIds = [...new Set([...sentMessages, ...receivedMessages])].filter(
      (id) => id.toString() !== req.user.id.toString()
    );

    const conversations = await User.find({ _id: { $in: conversationUserIds } }).select(
      'name email status statusUpdatedAt'
    );
    res.json(
      conversations.map((user) => ({ ...user.toObject(), _id: user._id.toString() }))
    );
  } catch (err) {
    console.error('❌ Error fetching conversations:', err.message);
    res.status(500).json({ message: 'Server error fetching conversations' });
  }
});

app.get('/api/messages/:userId', authMiddleware, async (req, res) => {
  try {
    const otherUserId = req.params.userId;
    if (req.user.id.toString() === otherUserId) {
      return res.status(400).json({ message: 'Cannot fetch messages with yourself' });
    }

    const messages = await Message.find({
      $or: [
        { sender: req.user.id, receiver: otherUserId },
        { sender: otherUserId, receiver: req.user.id },
      ],
    }).sort({ createdAt: 1 });

    const formattedMessages = messages.map((msg) => ({
      ...msg.toObject(),
      _id: msg._id.toString(),
      sender: msg.sender.toString(),
      receiver: msg.receiver.toString(),
    }));

    await Message.updateMany(
      { sender: otherUserId, receiver: req.user.id, read: false },
      { $set: { read: true } }
    );

    res.json(formattedMessages);
  } catch (err) {
    console.error('❌ Error fetching messages:', err.message);
    res.status(500).json({ message: 'Server error fetching messages' });
  }
});

app.post('/api/messages', authMiddleware, async (req, res) => {
  try {
    const { receiverId, content } = req.body;
    if (!content || !receiverId) {
      return res.status(400).json({ message: 'Message content and receiver are required' });
    }

    if (req.user.id.toString() === receiverId) {
      return res.status(400).json({ message: 'Cannot send messages to yourself' });
    }

    const receiver = await User.findById(receiverId);
    if (!receiver) return res.status(404).json({ message: 'Receiver not found' });

    const newMessage = new Message({
      sender: req.user.id,
      receiver: receiverId,
      content,
    });

    await newMessage.save();
    res.json({
      ...newMessage.toObject(),
      _id: newMessage._id.toString(),
      sender: newMessage.sender.toString(),
      receiver: newMessage.receiver.toString(),
    });
  } catch (err) {
    console.error('❌ Error sending message:', err.message);
    res.status(500).json({ message: 'Server error sending message' });
  }
});

app.put('/api/messages/:messageId/read', authMiddleware, async (req, res) => {
  try {
    const messageId = req.params.messageId;
    const message = await Message.findById(messageId);

    if (!message || message.receiver.toString() !== req.user.id.toString()) {
      return res.status(403).json({ message: 'Not authorized or message not found' });
    }

    message.read = true;
    await message.save();
    res.json({ success: true });
  } catch (err) {
    console.error('❌ Error marking message as read:', err.message);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/messages/unread/count', authMiddleware, async (req, res) => {
  try {
    const count = await Message.countDocuments({
      receiver: req.user.id,
      read: false,
    });
    res.json({ count });
  } catch (err) {
    console.error('❌ Error fetching unread count:', err.message);
    res.status(500).json({ message: 'Server error fetching unread count' });
  }
});

app.get('/api/messages/unread/counts-by-sender', authMiddleware, async (req, res) => {
  try {
    const unreadMessages = await Message.aggregate([
      { $match: { receiver: new mongoose.Types.ObjectId(req.user.id), read: false } },
      { $group: { _id: '$sender', count: { $sum: 1 } } },
    ]);

    const countsBySender = unreadMessages.reduce((acc, item) => {
      acc[item._id.toString()] = item.count;
      return acc;
    }, {});
    res.json(countsBySender);
  } catch (err) {
    console.error('❌ Error fetching unread counts by sender:', err.message);
    res.status(500).json({ message: 'Server error' });
  }
});

// Start Server
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});