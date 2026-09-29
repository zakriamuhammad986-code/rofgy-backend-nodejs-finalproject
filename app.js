const express = require('express');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const path = require('path');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'your_secret_key';

mongoose.set('strictQuery', false);

const uri =  "mongodb://root:<replace password>@localhost:27017";
mongoose.connect(uri,{'dbName':'SocialDB'});

const User = mongoose.model('User', { username: String, email: String, password: String });
const Post = mongoose.model('Post', { userId: mongoose.Schema.Types.ObjectId, text: String });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: SECRET_KEY, resave: false, saveUninitialized: true, cookie: { secure: false } }));

function authenticateJWT(req, res, next) {
  const token = req.session.token;
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

function requireAuth(req, res, next) {
  const token = req.session.token;
  if (!token) return res.redirect('/login');
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    return res.redirect('/login');
  }
}

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/post', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'post.html')));
app.get('/index', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const newUser = new User({ username, email, password });
    await newUser.save();

    const token = jwt.sign({ userId: newUser._id, username: newUser.username }, SECRET_KEY, { expiresIn: '1h' });
    req.session.token = token;

    res.send({"message":`The user ${username} has been added`});
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username, password });

    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    req.session.token = token;

    res.send({"message":`${user.username} has logged in`});
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/post', authenticateJWT, async (req, res) => {
  const { text } = req.body;

  if (!text || typeof text !== 'string') {
    return res.status(400).json({ message: 'Please provide valid post content' });
  }

  try {
    const newPost = new Post({ userId: req.user.userId, text });
    await newPost.save();
    res.status(201).json({ message: 'Post created successfully', post: newPost });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.get('/posts', authenticateJWT, async (req, res) => {
  try {
    const posts = await Post.find({ userId: req.user.userId });
    res.json({ posts });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.put('/posts/:postId', authenticateJWT, async (req, res) => {
  const postId = req.params.postId;
  const { text } = req.body;

  try {
    const post = await Post.findOneAndUpdate(
      { _id: postId, userId: req.user.userId },
      { text },
      { new: true }
    );

    if (!post) return res.status(404).json({ message: 'Post not found' });

    res.json({ message: 'Post updated successfully', updatedPost: post });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.delete('/posts/:postId', authenticateJWT, async (req, res) => {
  const postId = req.params.postId;

  try {
    const post = await Post.findOneAndDelete({ _id: postId, userId: req.user.userId });

    if (!post) return res.status(404).json({ message: 'Post not found' });

    res.json({ message: 'Post deleted successfully', deletedPost: post });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error(err);
    res.redirect('/login');
  });
});

app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
