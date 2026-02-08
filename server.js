
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());
app.use(helmet());

const PORT = 5003;
const MONGO_URI = process.env.URL;
const JWT_SECRET = 'ultra_secure_secret';

mongoose.connect(MONGO_URI).then(async () => {
    console.log('✅ Connected to MongoDB');
    const admin = await User.findOne({ role: 'admin' });
    if (!admin) {
        const hash = await bcrypt.hash('admin123', 10);
        await User.create({ name: 'System Admin', email: 'admin@tracker.com', password: hash, role: 'admin' });
        console.log('👑 Admin seeded: admin@tracker.com / admin123');
    }
});

const UserSchema = new mongoose.Schema({
    name: String, email: { type: String, unique: true }, password: String,
    role: { type: String, enum: ['admin', 'manager', 'developer', 'viewer'] }
});
const User = mongoose.model('User', UserSchema);

const ProjectSchema = new mongoose.Schema({
    title: String, description: String,
    manager: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    teamMembers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});
const Project = mongoose.model('Project', ProjectSchema);

const TicketSchema = new mongoose.Schema({
    title: String, description: String, 
    priority: { type: String, enum: ['Low', 'Medium', 'High', 'Urgent'] },
    status: { type: String, enum: ['To Do', 'In Progress', 'Done'], default: 'To Do' },
    assignee: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' }
}, { timestamps: true });
const Ticket = mongoose.model('Ticket', TicketSchema);

const CommentSchema = new mongoose.Schema({
    text: String,
    ticketId: { type: mongoose.Schema.Types.ObjectId, ref: 'Ticket' },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });
const Comment = mongoose.model('Comment', CommentSchema);


const auth = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(401).json({ msg: 'No token' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (e) { res.status(401).json({ msg: 'Invalid token' }); }
};


app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, role } = req.body;
    const hash = await bcrypt.hash(password, 10);
    await User.create({ name, email, password: hash, role: role || 'developer' });
    res.json({ msg: 'Registered' });
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET);
        res.json({ token, user: { id: user._id, name: user.name, role: user.role } });
    } else res.status(400).send('Invalid Credentials');
});


app.get('/api/users', auth, async (req, res) => {
    const users = await User.find({}, 'name role email');
    res.json(users);
});


app.post('/api/projects', auth, async (req, res) => {
    if (['developer', 'viewer'].includes(req.user.role)) return res.status(403).send('Forbidden');
    const managerId = req.user.role === 'admin' ? req.body.manager : req.user.id;
    const project = await Project.create({ ...req.body, manager: managerId });
    res.json(project);
});


// app.get('/api/projects', auth, async (req, res) => {
//     let query = {};
//     if (req.user.role === 'manager') query = { manager: req.user.id };
//     if (req.user.role === 'developer') query = { teamMembers: req.user.id };
//     res.json(await Project.find(query).populate('manager teamMembers', 'name'));
// });


// app.put('/api/projects/:id', auth, async (req, res) => {
//     const project = await Project.findById(req.params.id);
//     if (!project) return res.status(404).send('Not found');
//     if (req.user.role !== 'admin' && project.manager.toString() !== req.user.id) {
//         return res.status(403).json({ msg: 'Unauthorized' });
//     }
//     const updated = await Project.findByIdAndUpdate(req.params.id, req.body, { new: true });
//     res.json(updated);
// });

// 1. Projects API


app.put('/api/projects/:id', auth, async (req, res) => {
  const project = await Project.findById(req.params.id);
  // RESTRICTION: Only Admin or the specific Project Manager can edit
  if (req.user.role !== 'admin' && project.manager.toString() !== req.user.id) {
      return res.status(403).json({ msg: 'You do not own this project' });
  }
  const updated = await Project.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(updated);
});

// app.delete('/api/projects/:id', auth, async (req, res) => {
//     if (req.user.role !== 'admin') return res.status(403).send('Only admin can delete projects');
//     await Project.findByIdAndDelete(req.params.id);
//     await Ticket.deleteMany({ projectId: req.params.id });
//     res.json({ msg: 'Project deleted' });
// });

// Add/Update the Project Delete Route in server.js

app.delete('/api/projects/:id', auth, async (req, res) => {
  try {
      const project = await Project.findById(req.params.id);
      if (!project) return res.status(404).json({ msg: 'Project not found' });

      // PERMISSION CHECK: 
      // Only Admin OR the specific Manager who owns the project can delete it
      const isAdmin = req.user.role === 'admin';
      const isOwner = project.manager.toString() === req.user.id;

      if (!isAdmin && !isOwner) {
          return res.status(403).json({ msg: 'Unauthorized: Only the project manager or admin can delete this project' });
      }

      // 1. Find all tickets belonging to this project
      const tickets = await Ticket.find({ projectId: req.params.id });
      const ticketIds = tickets.map(t => t._id);

      // 2. Cascade Delete: Remove all comments linked to these tickets
      await Comment.deleteMany({ ticketId: { $in: ticketIds } });

      // 3. Cascade Delete: Remove all tickets
      await Ticket.deleteMany({ projectId: req.params.id });

      // 4. Finally, delete the project
      await project.deleteOne();

      res.json({ msg: 'Project and all associated data deleted successfully' });
  } catch (err) {
      res.status(500).json({ msg: 'Server Error during deletion' });
  }
});
app.post('/api/tickets', auth, async (req, res) => {
    if (req.user.role === 'viewer') return res.status(403).send('Forbidden');
    const ticket = await Ticket.create(req.body);
    res.json(ticket);
});


// app.get('/api/tickets', auth, async (req, res) => {
//     const { projectId } = req.query;
//     let query = { projectId };
//     if (req.user.role === 'developer') query.assignee = req.user.id;
//     res.json(await Ticket.find(query).populate('assignee', 'name'));
// });


app.put('/api/tickets/:id', auth, async (req, res) => {
    const ticket = await Ticket.findById(req.params.id);
    if (!ticket) return res.status(404).send('Ticket not found');
    const project = await Project.findById(ticket.projectId);

  
    if (req.body.commentText) {
        await Comment.create({ text: req.body.commentText, ticketId: req.params.id, userId: req.user.id });
    }


    if (req.user.role === 'developer') {
        const updated = await Ticket.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
        return res.json(updated);
    }


    if (req.user.role === 'admin' || project.manager.toString() === req.user.id) {
        const updated = await Ticket.findByIdAndUpdate(req.params.id, req.body, { new: true });
        return res.json(updated);
    }
    res.status(403).send('Not Authorized');
});

app.delete('/api/tickets/:id', auth, async (req, res) => {
    const ticket = await Ticket.findById(req.params.id);
    const project = await Project.findById(ticket.projectId);
    if (req.user.role === 'admin' || project.manager.toString() === req.user.id) {
        await Ticket.findByIdAndDelete(req.params.id);
        return res.json({ msg: 'Deleted' });
    }
    res.status(403).send('Unauthorized');
});


app.post('/api/comments', auth, async (req, res) => {
    const comment = await Comment.create({ ...req.body, userId: req.user.id });
    res.json(comment);
});

app.get('/api/comments/:ticketId', auth, async (req, res) => {
    const comments = await Comment.find({ ticketId: req.params.ticketId }).populate('userId', 'name').sort('-createdAt');
    res.json(comments);
});


app.put('/api/comments/:id', auth, async (req, res) => {
    const comment = await Comment.findById(req.params.id);
    if (comment.userId.toString() !== req.user.id) return res.status(403).send('Forbidden');
    comment.text = req.body.text;
    await comment.save();
    res.json(comment);
});


// app.delete('/api/comments/:id', auth, async (req, res) => {
//     const comment = await Comment.findById(req.params.id);
//     if (comment.userId.toString() === req.user.id || req.user.role === 'admin') {
//         await comment.deleteOne();
//         return res.json({ msg: 'Comment deleted' });
//     }
//     res.status(403).send('Forbidden');
// });


// app.get('/api/projects', auth, async (req, res) => {
//   let query = {};
//   if (req.user.role === 'manager') query = { manager: req.user.id };
//   // FIX: Developers see projects where they are in the teamMembers array
//   if (req.user.role === 'developer') query = { teamMembers: req.user.id };
//   res.json(await Project.find(query).populate('manager teamMembers', 'name email role'));
// });
app.get('/api/projects', auth, async (req, res) => {
  // Logic: Managers and Admins see all projects for collaboration, 
  // but the UI will restrict editing based on the 'manager' field.
  res.json(await Project.find().populate('manager teamMembers', 'name role email'));
});

// app.get('/api/tickets', auth, async (req, res) => {
//   const { projectId } = req.query;
//   if (!projectId) return res.status(400).send('Project ID required');

//   let query = { projectId };
  
//   // FIX: To ensure developers see tickets, we verify they are part of the project
//   // Removing the strict query.assignee filter so they can see all project tasks
//   // If you want them ONLY to see assigned ones, uncomment the line below:
//   // if (req.user.role === 'developer') query.assignee = req.user.id;

//   const tickets = await Ticket.find(query).populate('assignee', 'name');
//   res.json(tickets);
// })

app.get('/api/tickets', auth, async (req, res) => {
  const { projectId } = req.query;
  // Everyone in the system can see all tickets for transparency
  res.json(await Ticket.find({ projectId }).populate('assignee', 'name'));
});

// 3. Comments API
app.delete('/api/comments/:id', auth, async (req, res) => {
  const comment = await Comment.findById(req.params.id);
  const ticket = await Ticket.findById(comment.ticketId);
  const project = await Project.findById(ticket.projectId);

  // RESTRICTION: Comment can be deleted by the author, the Admin, or the Project Manager
  const isAuthor = comment.userId.toString() === req.user.id;
  const isProjectManager = project.manager.toString() === req.user.id;
  const isAdmin = req.user.role === 'admin';

  if (isAuthor || isProjectManager || isAdmin) {
      await comment.deleteOne();
      return res.json({ msg: 'Deleted' });
  }
  res.status(403).json({ msg: 'Unauthorized' });
});
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
