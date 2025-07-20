// Required modules
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cors = require('cors');
const http = require('http');
const nodemailer = require('nodemailer');
const { Server } = require('socket.io');

// Email Transporter (use your real Gmail and app password)
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: {
    user: 'zumalipas@gmail.com', // your email here
    pass: 'xsds bimk ndlb vmrr', // your app password here
  },
});

// Init app and server
const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = 3000;

// Connect MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/schoolsite')
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// Schemas & Models
const userSchema = new mongoose.Schema({
  fullname: String,
  email: { type: String, unique: true },
  phone: String,
  password: String,
  role: String, // admin, teacher, student, parent, sponsor, other
  subjects: [String],
  verified: { type: Boolean, default: false },
  photo: String,
  classLevel: String,
  linkedin: String,
  otp: String,
  otpExpires: Date,
});

const bookSchema = new mongoose.Schema({
  subject: String,
  title: String,
  description: String,
  image: String,
  file: String,
  uploadedBy: mongoose.Schema.Types.ObjectId,
  createdAt: { type: Date, default: Date.now },
  likes: { type: Number, default: 0 },
  dislikes: { type: Number, default: 0 },
  views: { type: Number, default: 0 },
  comments: [{ user: String, comment: String, createdAt: Date }],
});

const questionSchema = new mongoose.Schema({
  subject: String,
  questionText: String,
  questionImage: String,
  questionVideo: String,
  questionAudio: String,
  questionPDF: String,
  answer: String,
  uploadedBy: mongoose.Schema.Types.ObjectId,
  createdAt: { type: Date, default: Date.now },
  likes: { type: Number, default: 0 },
  dislikes: { type: Number, default: 0 },
  views: { type: Number, default: 0 },
  comments: [{ user: String, comment: String, createdAt: Date }],
});

const pastPaperSchema = new mongoose.Schema({
  year: String,
  subject: String,
  level: String,
  title: String,
  description: String,
  file: String,
  uploadedBy: mongoose.Schema.Types.ObjectId,
  createdAt: { type: Date, default: Date.now },
  likes: { type: Number, default: 0 },
  dislikes: { type: Number, default: 0 },
  views: { type: Number, default: 0 },
  comments: [{ user: String, comment: String, createdAt: Date }],
});

const videoSchema = new mongoose.Schema({
  subject: String,
  description: String,
  topic: String,
  level: String,
  videoFile: String,
  audioFile: String,
  photo: String,
  externalLink: String,
  uploadedBy: mongoose.Schema.Types.ObjectId,
  createdAt: { type: Date, default: Date.now },
});

const sportsGameSchema = new mongoose.Schema({
  title: String,
  description: String,
  mediaFile: String,
  category: String,
  uploadedBy: mongoose.Schema.Types.ObjectId,
  createdAt: { type: Date, default: Date.now },
});

const sportsGameQuestionSchema = new mongoose.Schema({
  question: String,
  answer: String,
  createdAt: { type: Date, default: Date.now },
});

const chatMessageSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  username: String,
  text: String,
  fileUrl: String,
  fileType: String,
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Book = mongoose.model('Book', bookSchema);
const Question = mongoose.model('Question', questionSchema);
const PastPaper = mongoose.model('PastPaper', pastPaperSchema);
const Video = mongoose.model('Video', videoSchema);
const SportsGame = mongoose.model('SportsGame', sportsGameSchema);
const SportsGameQuestion = mongoose.model('SportsGameQuestion', sportsGameQuestionSchema);
const ChatMessage = mongoose.model('ChatMessage', chatMessageSchema);

// Middleware setup
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'supersecretkey',
  resave: false,
  saveUninitialized: false,
}));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// Multer config for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
});
const upload = multer({ storage });

// Helper middleware
function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === 'admin') next();
  else res.redirect('/adminreg.html');
}

function isAuthenticated(req, res, next) {
  if (req.session.user) next();
  else res.redirect('/login.html');
}

// --- ROUTES ---

// Admin Registration
app.post('/admin/register', async (req, res) => {
  try {
    const { fullname, email, password } = req.body;
    if(await User.findOne({ email })) return res.status(400).send('Email already registered');
    const hashed = await bcrypt.hash(password, 10);
    const admin = new User({ fullname, email, password: hashed, role: 'admin', verified: true });
    await admin.save();
    req.session.user = admin;
    res.redirect('/admin.html');
  } catch (e) {
    console.error(e);
    res.status(500).send('Server error during admin registration');
  }
});

// Admin Login
app.post('/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, role: 'admin' });
    if (!user) return res.status(400).send('Invalid credentials');
    if (!await bcrypt.compare(password, user.password)) return res.status(400).send('Invalid credentials');
    req.session.user = user;
    res.redirect('/admin.html');
  } catch (e) {
    console.error(e);
    res.status(500).send('Server error during admin login');
  }
});

// Admin page protected
app.get('/admin.html', isAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Upload book
app.post('/upload/book', isAdmin, upload.fields([{ name: 'image', maxCount: 1 }, { name: 'file', maxCount: 1 }]), async (req, res) => {
  try {
    const { subject, title, description } = req.body;
    const image = req.files['image'] ? `/uploads/${req.files['image'][0].filename}` : '';
    const file = req.files['file'] ? `/uploads/${req.files['file'][0].filename}` : '';
    const book = new Book({ subject, title, description, image, file, uploadedBy: req.session.user._id });
    await book.save();
    res.redirect('/admin.html');
  } catch (e) {
    console.error(e);
    res.status(500).send('Error uploading book');
  }
});

// Get books (with search filter by subject or title)
app.get('/books', async (req, res) => {
  try {
    const { search } = req.query;
    let query = {};
    if (search) {
      const regex = new RegExp(search, 'i');
      query = { $or: [{ subject: regex }, { title: regex }] };
    }
    const books = await Book.find(query).sort({ createdAt: -1 });
    res.json(books);
  } catch (e) {
    console.error(e);
    res.status(500).send('Error fetching books');
  }
});

// Upload question
app.post('/upload/question', isAdmin, upload.fields([
  { name: 'questionImage', maxCount: 1 },
  { name: 'questionVideo', maxCount: 1 },
  { name: 'questionAudio', maxCount: 1 },
  { name: 'questionPDF', maxCount: 1 },
]), async (req, res) => {
  try {
    const { subject, questionText, answer } = req.body;
    const question = new Question({
      subject,
      questionText,
      answer,
      uploadedBy: req.session.user._id,
      questionImage: req.files['questionImage'] ? `/uploads/${req.files['questionImage'][0].filename}` : '',
      questionVideo: req.files['questionVideo'] ? `/uploads/${req.files['questionVideo'][0].filename}` : '',
      questionAudio: req.files['questionAudio'] ? `/uploads/${req.files['questionAudio'][0].filename}` : '',
      questionPDF: req.files['questionPDF'] ? `/uploads/${req.files['questionPDF'][0].filename}` : '',
    });
    await question.save();
    res.redirect('/admin.html');
  } catch (e) {
    console.error(e);
    res.status(500).send('Error uploading question');
  }
});

// Get questions (with optional subject search)
app.get('/questions', async (req, res) => {
  try {
    const { search } = req.query;
    let query = {};
    if (search) {
      const regex = new RegExp(search, 'i');
      query = { subject: regex };
    }
    const questions = await Question.find(query).sort({ createdAt: -1 });
    res.json(questions);
  } catch (e) {
    console.error(e);
    res.status(500).send('Error fetching questions');
  }
});

// Upload past paper
app.post('/upload/pastpaper', isAdmin, upload.single('file'), async (req, res) => {
  try {
    const { year, subject, level, title, description } = req.body;
    const file = req.file ? `/uploads/${req.file.filename}` : '';
    const pastpaper = new PastPaper({ year, subject, level, title, description, file, uploadedBy: req.session.user._id });
    await pastpaper.save();
    res.redirect('/admin.html');
  } catch (e) {
    console.error(e);
    res.status(500).send('Error uploading past paper');
  }
});

// Get past papers (with optional search filter by year or subject)
app.get('/pastpapers', async (req, res) => {
  try {
    const { search } = req.query;
    let query = {};
    if (search) {
      const regex = new RegExp(search, 'i');
      query = { $or: [{ year: regex }, { subject: regex }] };
    }
    const papers = await PastPaper.find(query).sort({ createdAt: -1 });
    res.json(papers);
  } catch (e) {
    console.error(e);
    res.status(500).send('Error fetching past papers');
  }
});

// Upload teaching/practical video
app.post('/upload/video', isAdmin, upload.fields([
  { name: 'videoFile', maxCount: 1 },
  { name: 'audioFile', maxCount: 1 },
  { name: 'photo', maxCount: 1 },
]), async (req, res) => {
  try {
    const { subject, description, topic, level, externalLink } = req.body;
    const video = new Video({
      subject,
      description,
      topic,
      level,
      videoFile: req.files['videoFile'] ? `/uploads/${req.files['videoFile'][0].filename}` : '',
      audioFile: req.files['audioFile'] ? `/uploads/${req.files['audioFile'][0].filename}` : '',
      photo: req.files['photo'] ? `/uploads/${req.files['photo'][0].filename}` : '',
      externalLink,
      uploadedBy: req.session.user._id,
    });
    await video.save();
    res.redirect('/admin.html');
  } catch (e) {
    console.error(e);
    res.status(500).send('Error uploading video');
  }
});

// Get videos
app.get('/videos', async (req, res) => {
  try {
    const videos = await Video.find().sort({ createdAt: -1 });
    res.json(videos);
  } catch (e) {
    console.error(e);
    res.status(500).send('Error fetching videos');
  }
});

// Upload sports media
app.post('/upload/sportsmedia', isAdmin, upload.single('mediaFile'), async (req, res) => {
  try {
    const { title, description, category } = req.body;
    const mediaFile = req.file ? `/uploads/${req.file.filename}` : '';
    const sg = new SportsGame({ title, description, category, mediaFile, uploadedBy: req.session.user._id });
    await sg.save();
    res.redirect('/admin.html');
  } catch (e) {
    console.error(e);
    res.status(500).send('Error uploading sports media');
  }
});

// Get sports media
app.get('/sportsmedia', async (req, res) => {
  try {
    const sports = await SportsGame.find().sort({ createdAt: -1 });
    res.json(sports);
  } catch (e) {
    console.error(e);
    res.status(500).send('Error fetching sports media');
  }
});

// Add sports game question
app.post('/upload/sportsgamequestion', isAdmin, async (req, res) => {
  try {
    const { question, answer } = req.body;
    const q = new SportsGameQuestion({ question, answer });
    await q.save();
    res.redirect('/admin.html');
  } catch (e) {
    console.error(e);
    res.status(500).send('Error adding sports game question');
  }
});

// Get sports game questions
app.get('/sportsgamequestions', async (req, res) => {
  try {
    const questions = await SportsGameQuestion.find();
    res.json(questions);
  } catch (e) {
    console.error(e);
    res.status(500).send('Error fetching sports game questions');
  }
});

// User Registration (all roles)
app.post('/register', upload.single('photo'), async (req, res) => {
  try {
    const { fullname, email, phone, password, confirmPassword, role, classLevel, subjects } = req.body;
    if (password !== confirmPassword) return res.status(400).send('Passwords do not match');
    if (await User.findOne({ email })) return res.status(400).send('Email already registered');
    const hashed = await bcrypt.hash(password, 10);

    const userData = {
      fullname,
      email,
      phone,
      password: hashed,
      role,
      classLevel: classLevel || '',
      photo: req.file ? `/uploads/${req.file.filename}` : '',
      verified: role === 'teacher' ? false : true, // teachers wait approval
      subjects: subjects ? (Array.isArray(subjects) ? subjects : [subjects]) : [],
    };

    const user = new User(userData);
    await user.save();

    // Optionally notify admin to verify teachers here (email or other)

    res.redirect('/login.html');
  } catch (e) {
    console.error(e);
    res.status(500).send('Error during registration');
  }
});

// User Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).send('Invalid credentials');
    if (!user.verified) return res.status(403).send('Your account is not verified yet');
    if (!await bcrypt.compare(password, user.password)) return res.status(400).send('Invalid credentials');
    req.session.user = user;
    res.redirect('/profile.html');
  } catch (e) {
    console.error(e);
    res.status(500).send('Login error');
  }
});

// Profile protected route
app.get('/profile.html', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

// Password Reset - Request OTP
app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).send('User not found');

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp;
    user.otpExpires = new Date(Date.now() + 10 * 60000); // 10 mins expiry
    await user.save();

    await transporter.sendMail({
      from: 'zumalipas@gmail.com',
      to: user.email,
      subject: 'Password Reset Code',
      text: `Your OTP code is: ${otp}`,
    });

    res.send('OTP sent to email');
  } catch (e) {
    console.error(e);
    res.status(500).send('Error sending OTP');
  }
});

// Password Reset - Submit New Password
app.post('/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    const user = await User.findOne({ email });
    if (!user || user.otp !== otp || user.otpExpires < Date.now())
      return res.status(400).send('Invalid or expired OTP');

    user.password = await bcrypt.hash(newPassword, 10);
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    res.send('Password reset successful');
  } catch (e) {
    console.error(e);
    res.status(500).send('Error resetting password');
  }
});

// --- CHAT ROUTES ---

// Get all chat messages
app.get('/chat/messages', isAuthenticated, async (req, res) => {
  try {
    const messages = await ChatMessage.find().sort({ createdAt: 1 });
    res.json(messages);
  } catch (e) {
    console.error(e);
    res.status(500).send('Error fetching chat messages');
  }
});

// Post chat message with optional file attachment
app.post('/chat', isAuthenticated, upload.single('attachment'), async (req, res) => {
  try {
    const { message } = req.body;
    const file = req.file;

    let fileUrl = '', fileType = '';
    if (file) {
      fileUrl = `/uploads/${file.filename}`;
      fileType = file.mimetype;
    }

    const chatMsg = new ChatMessage({
      userId: req.session.user._id,
      username: req.session.user.fullname,
      text: message,
      fileUrl,
      fileType,
    });
    await chatMsg.save();

    io.emit('newMessage', chatMsg);

    res.redirect('/chattingroom.html');
  } catch (e) {
    console.error('Chat error:', e);
    res.status(500).send('Chat failed');
  }
});

// Socket.IO connection
io.on('connection', (socket) => {
  console.log('🟢 User connected');
  socket.on('disconnect', () => {
    console.log('🔴 User disconnected');
  });
});

// Start server
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
