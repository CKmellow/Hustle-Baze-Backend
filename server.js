require('dotenv').config();
const jwt = require('jsonwebtoken');
const express = require('express');
const bcrypt = require('bcryptjs');
const { MongoClient, ObjectId } = require('mongodb');
const crypto = require("crypto");
const cors = require('cors');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const { Readable } = require('stream');
const axios = require('axios');


const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

//const upload = multer({ storage });



const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');

const app = express();
// const port = 5000;
const port = process.env.PORT || 5000;

// app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// Middleware
// app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : ['http://localhost:3000'];

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (mobile apps, curl, etc.)
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
        return callback(null, true);
      } else {
        console.log(`Blocked CORS request from origin: ${origin}`);
        return callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static('uploads'));


// //Configure file upload storage
// const storage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     const uploadDir = 'uploads/';
//     if (!fs.existsSync(uploadDir)) {
//       fs.mkdirSync(uploadDir);
//     }
//     cb(null, uploadDir);
//   },
//   filename: (req, file, cb) => {
//     const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
//     cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
//   }
// });
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const upload = multer({ 
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Only PDF files are allowed'), false);
    }
  },
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

const uri = "mongodb+srv://Admin:Hustlebase@hustle-base.goii2xv.mongodb.net/?retryWrites=true&w=majority&appName=Hustle-Base";
const client = new MongoClient(uri);
const jwtSecret = process.env.JWT_SECRET;
// console.log("Loaded JWT Secret:", jwtSecret);


// Connect to the MongoDB database
async function connectToDb() {
    try {
        await client.connect();
        console.log('Connected to MongoDB');
        return client.db("Hustle-db");
    } catch (error) {
        console.error('Error connecting to MongoDB:', error);
        throw new Error('Failed to connect to the database');
    }
}



// Middleware for Authentication
const authMiddleware = async (req, res, next) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];    
    if (!token) return res.status(401).json({ message: "Not authenticated" });

    try {
        const decoded = jwt.verify(token, jwtSecret);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: "Invalid token" });
    }
};

// Verify if token is still valid
app.get('/api/verify-token', authMiddleware, async (req, res) => {
  return res.status(200).json({ success: true, message: 'Token is valid' });
});

// POST: Secure Login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "Both email and password are required." });
    }

    try {
        const db = await connectToDb();
        const usersCollection = db.collection("users");

        const user = await usersCollection.findOne({ email: email });

        if (!user) {
            return res.status(400).json({ message: "Invalid credentials." });
        }

        if (!user.verified) {
            return res.status(401).json({ message: "Please verify your email before logging in." });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid credentials." });
        }

        const token = jwt.sign(
            { _id: user._id, role: user.role },
            jwtSecret,
            { expiresIn: "2h" }
        );

        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax'
        });

        return res.json({ token, user });

    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ message: "Server error. Please try loggin in later." });
    }
});

app.post('/signup', async (req, res) => {
    const { fname, lname, email, password, role, OrgName, location, phone, description } = req.body;

    if (!fname || !lname || !email || !password || !role) {
        return res.status(400).json({ message: "All required fields (fname, lname, email, password, role) must be provided." });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ message: "Invalid email format." });
    }

    try {
        const db = await connectToDb();
        const usersCollection = db.collection("users");

        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "Email already exists." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationToken = crypto.randomBytes(32).toString('hex');
        const userId = new ObjectId(); // ObjectId for users table

        const newUser = {
            _id: userId,
            fname,
            lname,
            email,
            password: hashedPassword,
            role,
            verified: false,
            verificationToken,
            createdAt: new Date()
        };

        await usersCollection.insertOne(newUser);

        // Insert into related collection
        if (role === 'student') {
            await db.collection("Students").insertOne({
                userID: userId,
                studentID: null, // To be filled in later after login
                dob: null,
                phone: "",
                course: "",
                yearOfStudy: "",
                OrgName: "",
                description: ""
            });
        } else if (role === 'employer') {
            await db.collection("Employer").insertOne({
                userID: userId,
                OrgName: OrgName || "",
                location: location || "",
                phone: phone || "",
                email: email,
                description: description || ""
            });
        }

        // Send verification email
        const verificationLink = `http://localhost:5000/verify-email?token=${verificationToken}`;

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Verify Your Email',
            html: `<h2>Welcome to HustleBase 👋</h2>
                   <p>Please verify your email by clicking the link below:</p>
                   <a href="${verificationLink}">Verify Email</a>`
        });

        return res.status(201).json({ message: "Signup successful. Please verify your email." });

    } catch (error) {
        console.error("Signup error:", error);
        return res.status(500).json({ message: "Internal server error during signup." });
    }
});

app.get('/verify-email', async (req, res) => {
    const token = req.query.token;

    if (!token) {
        return res.status(400).send('Invalid or missing token');
    }

    try {
        const db = await connectToDb();
        const usersCollection = db.collection("users");

        const user = await usersCollection.findOne({ verificationToken: token });

        if (!user) {
            return res.status(400).send('Invalid verification token.');
        }

        // Update the user to mark them as verified
        await usersCollection.updateOne(
            { _id: user._id },
            { $set: { verified: true }, $unset: { verificationToken: "" } }
        );

        // ✅ Redirect to login page
        res.redirect('http://localhost:3000/login');
    } catch (err) {
        console.error("Verification error:", err);
        res.status(500).send("Server error while verifying email.");
    }
});

// Applications API Endpoints
app.get('/api/applications', authMiddleware, async (req, res) => {
    try {
        const { feedback, sortBy, search } = req.query;
        const studentID = new ObjectId(req.user._id);
        
        const db = await connectToDb();
        const applicationsCollection = db.collection("Applications");
        
        let query = { studentID };
        
        if (feedback && ['pending', 'approved', 'rejected'].includes(feedback)) {
            query.feedback = feedback;
        }
        
        if (search) {
            query.$or = [
                { 'internship.title': { $regex: search, $options: 'i' } },
                { 'internship.company': { $regex: search, $options: 'i' } }
            ];
        }
        
        let sortOption = { createdAt: -1 }; // Default: newest first
        if (sortBy === 'oldest') {
            sortOption = { createdAt: 1 };
        }
        
        const applications = await applicationsCollection.find(query)
            .sort(sortOption)
            .toArray();
            
        res.json(applications);
    } catch (err) {
        console.error("Error fetching applications:", err);
        res.status(500).json({ message: err.message });
    }
});

// Upload documents for application
app.post('/api/applications/:id/documents', authMiddleware, upload.fields([
  { name: 'coverLetter', maxCount: 1 },
  { name: 'cv', maxCount: 1 }
]), async (req, res) => {
  try {
    const db = await connectToDb();
    const applicationsCollection = db.collection("Applications");

    const application = await applicationsCollection.findOne({
      _id: new ObjectId(req.params.id),
      studentID: req.user._id
    });

    if (!application) {
      return res.status(404).json({ message: 'Application not found' });
    }

    const updateData = {};
    if (req.files.coverLetter) {
      updateData.coverLetter = req.files.coverLetter[0].path;  // store file path
    }

    if (req.files.cv) {
      updateData.cv = req.files.cv[0].path;  // store file path
    }

    const result = await applicationsCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: updateData }
    );

    res.json({ message: 'Documents uploaded successfully', modifiedCount: result.modifiedCount });
  } catch (err) {
    console.error("Error uploading documents:", err);
    res.status(400).json({ message: err.message });
  }
});

// app.post('/api/applications/:id/documents', authMiddleware, upload.fields([
//     { name: 'coverLetter', maxCount: 1 },
//     { name: 'cv', maxCount: 1 }
// ]), async (req, res) => {
//     try {
//         const db = await connectToDb();
//         const applicationsCollection = db.collection("Applications");
        
//         const application = await applicationsCollection.findOne({
//             _id: new ObjectId(req.params.id),
//             studentID: req.user._id
//         });
        
//         if (!application) {
//             return res.status(404).json({ message: 'Application not found' });
//         }
        
//         const updateData = {};
//         if (req.files.coverLetter) {
//             updateData.coverLetter = req.files.coverLetter[0].path;
//         }
        
//         if (req.files.cv) {
//             updateData.cv = req.files.cv[0].path;
//         }
        
//         const result = await applicationsCollection.updateOne(
//             { _id: new ObjectId(req.params.id) },
//             { $set: updateData }
//         );
        
//         res.json({ message: 'Documents uploaded successfully', modifiedCount: result.modifiedCount });
//     } catch (err) {
//         console.error("Error uploading documents:", err);
//         res.status(400).json({ message: err.message });
//     }
// });
// DELETE /api/applications/:id
app.delete('/api/applications/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { ObjectId } = require('mongodb');

  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ message: 'Invalid application ID' });
  }

  try {
    const db = await connectToDb();
    const result = await db.collection('Applications').deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: 'Application not found' });
    }

    res.status(200).json({ message: 'Application deleted successfully' });
  } catch (error) {
    console.error('Delete application error:', error);
    res.status(500).json({ message: 'Server error while deleting application' });
  }
});




// Get application status counts
app.get('/api/student/:studentID/application-status-counts', authMiddleware, async (req, res) => {
  try {
    const studentID = new ObjectId(req.params.studentID.trim());
    const userID = new ObjectId(req.user._id);

    if (userID.toString() !== studentID.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const db = await connectToDb();
    const applicationsCollection = db.collection("Applications");

    const counts = await applicationsCollection.aggregate([
      { $match: { studentID } },
      { $group: { _id: "$feedback", count: { $sum: 1 } } }
    ]).toArray();

    const response = {
      pending: 0,
      approved: 0,
      rejected: 0,
      profileCompletion: 0,
      alerts: []
    };

    counts.forEach(item => {
      const key = item._id?.toLowerCase();
      if (response.hasOwnProperty(key)) {
        response[key] = item.count;
      }
    });

    res.status(200).json(response);
  } catch (error) {
    console.error("Error getting application counts:", error);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});


app.get('/api/employers/:employerID/application-status-counts', authMiddleware, async (req, res) => {
  const ObjectId = require('mongodb').ObjectId;
  const employerID = req.params.employerID;

  if (!ObjectId.isValid(employerID)) {
    return res.status(400).json({ success: false, message: 'Invalid employer ID' });
  }

  try {
    const db = await connectToDb();

    // Get all internships by this employer
    const internshipsCollection = db.collection("Internships");
    const internshipDocs = await internshipsCollection.find({ employerId: new ObjectId(employerID) }).toArray();

    const internshipIds = internshipDocs.map(doc => doc._id);

    // Count applications by status across all internships posted by this employer
    const applicationsCollection = db.collection("Applications");
    const counts = await applicationsCollection.aggregate([
      { $match: { internshipID: { $in: internshipIds } } },
      { $group: { _id: "$feedback", count: { $sum: 1 } } }
    ]).toArray();

    const response = {
      pending: 0,
      approved: 0,
      rejected: 0
    };

    counts.forEach(item => {
      const key = item._id.toLowerCase();
      if (response.hasOwnProperty(key)) {
        response[key] = item.count;
      }
    });

    res.status(200).json({
      success: true,
      applicationCounts: response,
      internshipCount: internshipDocs.length 
    });
  } catch (error) {
    console.error("Dashboard stats error:", error);
    res.status(500).json({ success: false, message: "Server error. Try again later." });
  }
});


// Get all internships with filters
app.get('/api/filter/internships', async (req, res) => {
  try {
    const { title, location, company, deadline } = req.query;
    const db = await connectToDb();
    const internshipsCollection = db.collection("Internships");

    let query = {};

    if (title) {
      query.title = { $regex: title, $options: 'i' };
    }

    if (location) {
      query.location = { $regex: location, $options: 'i' };
    }

    if (company) {
      query.company = { $regex: company, $options: 'i' };
    }

    if (deadline) {
      query.deadline = { $gte: new Date(deadline) };
    }

    const internships = await internshipsCollection.find(query).toArray();
    res.json(internships);
  } catch (err) {
    console.error("Error fetching internships:", err);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});

// File upload endpoint
app.post('/api/upload', upload.fields([
  { name: 'cv', maxCount: 1 },
  { name: 'coverLetter', maxCount: 1 }
]), async (req, res) => {
  try {
    const fileKey = req.files.cv ? 'cv' : 'coverLetter';

    if (!req.files || !req.files[fileKey] || !req.files[fileKey][0]) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const file = req.files[fileKey][0];
    res.json({ filePath: file.path });
  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ message: "File upload failed", error: err.message });
  }
});


// Create new application
app.post('/api/create/applications', authMiddleware, async (req, res) => {
  try {
    const db = await connectToDb();
    const Applications = db.collection('Applications');
    const Users = db.collection('Users');

    const {
      internship,
      coverLetter,
      cv,
      feedback = 'pending',
      applicationDate = new Date().toISOString()
    } = req.body;

    if (!internship || !coverLetter || !cv) {
      return res.status(400).json({ message: 'Internship, CV, and Cover Letter are required' });
    }

    const existing = await Applications.findOne({
      studentID: new ObjectId(req.user._id),
      internshipID: new ObjectId(internship)
    });

    if (existing) {
      return res.status(409).json({ message: 'You have already applied for this internship' });
    }

    const newApplication = {
      internshipID: new ObjectId(internship),
      studentID: new ObjectId(req.user._id),
      feedback,
      coverLetter,
      cv,
      applicationDate: new Date(applicationDate),
      createdAt: new Date()
    };

    const result = await Applications.insertOne(newApplication);

    // Fetch user to get their email
    const student = await Users.findOne({ _id: new ObjectId(req.user._id) });

    if (student?.email) {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: student.email,
        subject: 'Internship Application Confirmation',
        html: `
          <h2>Application Submitted Successfully 🎉</h2>
          <p>Hello ${student.fname || 'Student'},</p>
          <p>Thank you for applying for the internship. Your application has been received and is under review.</p>
          <p><strong>Internship ID:</strong> ${internship}</p>
          <p><strong>Application Date:</strong> ${new Date(applicationDate).toLocaleDateString()}</p>
          <br>
          <p>Best regards,</p>
          <p>HustleBase Team</p>
        `
      });
    }

    res.status(201).json({ message: 'Application submitted and confirmation email sent.', applicationId: result.insertedId });
  } catch (err) {
    console.error('Error submitting application:', err);
    res.status(500).json({ message: 'Failed to submit application' });
  }
});

// app.post('/api/create/applications', authMiddleware, async (req, res) => {
//   try {
//     const db = await connectToDb();
//     const Applications = db.collection('Applications');

//     const {
//       internship,       
//       coverLetter,      
//       cv,               
//       feedback = 'pending',
//       // status = 'pending',
//       applicationDate = new Date().toISOString()
//     } = req.body;

//     if (!internship || !coverLetter || !cv) {
//       return res.status(400).json({ message: 'Internship, CV, and Cover Letter are required' });
//     }

//     // Check if already applied
//     const existing = await Applications.findOne({
//       studentID: new ObjectId(req.user._id),
//       internshipID: new ObjectId(internship)
//     });

//     if (existing) {
//       return res.status(409).json({ message: 'You have already applied for this internship' });
//     }

//     const newApplication = {
//       internshipID: new ObjectId(internship),
//       studentID: new ObjectId(req.user._id),
//       //status,
//       feedback,
//       coverLetter,
//       cv,
//       applicationDate: new Date(applicationDate),
//       createdAt: new Date()
//     };

//     const result = await Applications.insertOne(newApplication);
//     res.status(201).json({ message: 'Application submitted successfully', applicationId: result.insertedId });
//   } catch (err) {
//     console.error('Error submitting application:', err);
//     res.status(500).json({ message: 'Failed to submit application' });
//   }
// });

app.get('/api/fetch/applications', authMiddleware, async (req, res) => {
  try {
    const db = await connectToDb();
    const applicationsCollection = db.collection("Applications");

    const { search, feedback, sortBy } = req.query;

    const matchStage = {
      studentID: new ObjectId(req.user._id)
    };

    if (feedback) {
      matchStage.feedback = feedback;
    }

    const pipeline = [
      { $match: matchStage },

      {
        $lookup: {
          from: "Internships",
          localField: "internshipID",
          foreignField: "_id",
          as: "internship"
        }
      },
      {
        $unwind: {
          path: "$internship",
          preserveNullAndEmptyArrays: true
        }
      },

      // Optional text search on internship title/company
      ...(search
        ? [{
            $match: {
              $or: [
                { "internship.title": { $regex: search, $options: "i" } },
                { "internship.company": { $regex: search, $options: "i" } }
              ]
            }
          }]
        : []
      ),

      {
        $project: {
          cv: 1,
          coverLetter: 1,
          feedback: 1,
          createdAt: 1,
          internship: {
            title: 1,
            company: 1,
            deadline: 1
          }
        }
      },

      {
        $sort: {
          createdAt: sortBy === 'oldest' ? 1 : -1
        }
      }
    ];

    const applications = await applicationsCollection.aggregate(pipeline).toArray();
    res.json(applications);
  } catch (err) {
    console.error("Error fetching applications:", err);
    res.status(500).json({ message: "Failed to fetch applications" });
  }
});


// // Get ALL internships (no filters)
// app.get('/api/internships', async (req, res) => {
//   try {
//     const db = await connectToDb();
//     const internships = await db.collection('Internships').find({}).toArray();
//     res.json(internships);
//   } catch (err) {
//     console.error('Error fetching internships:', err);
//     res.status(500).json({ message: 'Server error. Failed to fetch internships.' });
//   }
// });

// Get student profile
// GET student profile by userID
app.get('/api/students/by-user/:userId', authMiddleware, async (req, res) => {
  try {
    const userId = req.params.userId;

    if (!ObjectId.isValid(userId)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid user ID format'
      });
    }

    const db = await connectToDb();

    // Find the student with matching userID
    const student = await db.collection('Students').findOne({
      userID: new ObjectId(userId)
    });

    if (!student) {
      return res.status(404).json({
        success: false,
        message: 'Student not found for given user ID'
      });
    }

    // Get user info from Users collection
    const user = await db.collection('users').findOne({ _id: new ObjectId(userId) });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Associated user not found'
      });
    }

    const profile = {
      ...student,
      fname: user.fname,
      lname: user.lname,
      email: user.email
    };

    res.json({
      success: true,
      data: profile
    });
  } catch (err) {
    console.error('Error fetching student by userID:', err);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});


// PUT update student profile
app.put('/api/students/:id', authMiddleware, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid student ID format'
      });
    }

    const {
      fname,
      lname,
      studentID,
      dob,
      phone,
      course,
      yearOfStudy,
      OrgName,
      description
    } = req.body;

    // Validate required fields
    if (!studentID || !dob || !OrgName) {
      return res.status(400).json({
        success: false,
        message: 'Student ID, Date of Birth, and Organization Name are required',
        missingFields: {
          required: [
            ...(!studentID ? ['studentID'] : []),
            ...(!dob ? ['dob'] : []),
            ...(!OrgName ? ['OrgName'] : [])
          ]
        }
      });
    }

    // Age check
    const dobDate = new Date(dob);
    const today = new Date();
    let age = today.getFullYear() - dobDate.getFullYear();
    const m = today.getMonth() - dobDate.getMonth();
    if (m < 0 || (m === 0 && today.getDate() < dobDate.getDate())) {
      age--;
    }
    if (age < 18) {
      return res.status(400).json({
        success: false,
        message: 'Student must be at least 18 years old'
      });
    }

    const db = await connectToDb();

    // Update student fields
    const updateResult = await db.collection('Students').updateOne(
      { _id: new ObjectId(req.params.id) },
      {
        $set: {
          studentID,
          dob: dobDate,
          phone,
          course,
          yearOfStudy,
          OrgName,
          description,
          updatedAt: new Date()
        }
      }
    );

    if (updateResult.modifiedCount === 0) {
      return res.status(404).json({
        success: false,
        message: 'Student not found or no changes made'
      });
    }

    // Update fname and lname in Users (optional, editable)
    const student = await db.collection('Students').findOne({
      _id: new ObjectId(req.params.id)
    });

    await db.collection('users').updateOne(
      { _id: student.userID },
      {
        $set: {
          fname,
          lname
        }
      }
    );

    // Return updated student + user info
    const updatedUser = await db.collection('users').findOne({ _id: student.userID });
    const updatedStudent = await db.collection('Students').findOne({
      _id: new ObjectId(req.params.id)
    });

    res.json({
      success: true,
      message: 'Profile updated successfully',
      data: {
        ...updatedStudent,
        fname: updatedUser.fname,
        lname: updatedUser.lname,
        email: updatedUser.email
      }
    });
  } catch (err) {
    console.error('Error updating student:', err);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});



// Get profile completion percentage
app.get('/api/students/:id/completion', authMiddleware, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid student ID format' 
      });
    }

    const db = await connectToDb();
    const student = await db.collection('Students').findOne({ 
      userID: new ObjectId(req.params.id)
    });

    if (!student) {
      return res.status(404).json({ 
        success: false,
        message: 'Student not found' 
      });
    }

    const requiredFields = ['studentID', 'dob', 'OrgName'];
    const optionalFields = ['phone', 'course', 'yearOfStudy', 'description'];

    let score = 0;
    const missingFields = {
      required: [],
      optional: []
    };

    // Check required fields (1 point each)
    requiredFields.forEach(field => {
      if (student[field] && String(student[field]).trim() !== '') {
        score += 1;
      } else {
        missingFields.required.push(field);
      }
    });

    // Check optional fields (0.5 points each)
    optionalFields.forEach(field => {
      if (student[field] && String(student[field]).trim() !== '') {
        score += 0.5;
      } else {
        missingFields.optional.push(field);
      }
    });

    const maxScore = requiredFields.length + (optionalFields.length * 0.5);
    const percentage = Math.round((score / maxScore) * 100);

    res.json({ 
      success: true,
      profileCompletion: percentage,
      missingFields,
      lastUpdated: student.updatedAt || student.createdAt
    });

  } catch (err) {
    console.error('Profile completion error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Server error while calculating completion',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// GET employer profile completion + internship count
app.get('/api/employers/:id/completion', authMiddleware, async (req, res) => {
  const ObjectId = require('mongodb').ObjectId;

  try {
    const userId = req.params.id;

    if (!ObjectId.isValid(userId)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid employer user ID format'
      });
    }

    const db = await connectToDb();

    // Fetch employer by userID
    const employer = await db.collection('Employer').findOne({ userID: new ObjectId(userId) });

    if (!employer) {
      return res.status(404).json({
        success: false,
        message: 'Employer not found for given user ID'
      });
    }

    // ✅ Corrected field names
    const requiredFields = ['company'];
    const optionalFields = ['location', 'contact', 'description', 'website', 'requestVerification'];

    let score = 0;
    const missingFields = {
      required: [],
      optional: []
    };

    // Evaluate required fields
    requiredFields.forEach(field => {
      if (employer[field] && String(employer[field]).trim() !== '') {
        score += 1;
      } else {
        missingFields.required.push(field);
      }
    });

    // Evaluate optional fields
    optionalFields.forEach(field => {
      if (
        typeof employer[field] === 'boolean' ||
        (employer[field] && String(employer[field]).trim() !== '')
      ) {
        score += 0.5;
      } else {
        missingFields.optional.push(field);
      }
    });

    const maxScore = requiredFields.length + (optionalFields.length * 0.5);
    const percentage = Math.round((score / maxScore) * 100);

    // Count internships posted by employer
    const internshipCount = await db.collection('Internships').countDocuments({
      employerID: new ObjectId(userId)
    });

    res.json({
      success: true,
      profileCompletion: percentage,
      missingFields,
      internshipCount,
      lastUpdated: employer.updatedAt || employer.createdAt
    });

  } catch (err) {
    console.error('Employer completion error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error while calculating employer profile completeness',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});


// creating the admin table

app.get('/api/employers/by-user/:userId', authMiddleware, async (req, res) => {
  const userId = req.params.userId;
  if (!ObjectId.isValid(userId)) {
    return res.status(400).json({ success: false, message: 'Invalid user ID format' });
  }

  const db = await connectToDb();
  const employer = await db.collection('Employer').findOne({ userID: new ObjectId(userId) });
  const user = await db.collection('users').findOne({ _id: new ObjectId(userId) });

  if (!employer || !user) {
    return res.status(404).json({ success: false, message: 'Employer or user not found' });
  }

  res.json({
    success: true,
    data: {
      ...employer,
      fname: user.fname,
      lname: user.lname,
      email: user.email
    }
  });
});

app.put('/api/employers/:id', authMiddleware, async (req, res) => {
  const employerId = req.params.id;
  if (!ObjectId.isValid(employerId)) {
    return res.status(400).json({ success: false, message: 'Invalid employer ID' });
  }

  const {
    fname,
    lname,
    company,
    location,
    contact,
    description,
    website, // ✅ added
    requestVerification
  } = req.body;

  if (!company) {
    return res.status(400).json({
      success: false,
      message: 'Organization Name is required',
      missingFields: { required: ['company'] }
    });
  }

  const db = await connectToDb();

  const employer = await db.collection('Employer').findOne({ _id: new ObjectId(employerId) });
  if (!employer) {
    return res.status(404).json({ success: false, message: 'Employer not found' });
  }

  await db.collection('Employer').updateOne(
    { _id: new ObjectId(employerId) },
    {
      $set: {
        company,
        location,
        contact,
        description,
        website, // ✅ stored
        requestVerification: !!requestVerification,
        updatedAt: new Date()
      }
    }
  );

  await db.collection('users').updateOne(
    { _id: employer.userID },
    {
      $set: {
        fname,
        lname
      }
    }
  );

  res.json({ success: true, message: 'Profile updated successfully' });
});


// GET internships by employer ID
app.get('/api/employers/:id/internships', authMiddleware, async (req, res) => {
  const ObjectId = require('mongodb').ObjectId;
  const employerId = req.params.id;

  if (!ObjectId.isValid(employerId)) {
    return res.status(400).json({ success: false, message: 'Invalid employer ID' });
  }

  try {
    const db = await connectToDb();
    const internships = await db.collection('Internships')
      .find({ employerId: new ObjectId(employerId) })
      .toArray();

    res.status(200).json({ success: true, internships });
  } catch (error) {
    console.error("Error fetching internships:", error);
    res.status(500).json({ success: false, message: "Server error. Please try again later." });
  }
});

app.post('/api/create/internships', authMiddleware, async (req, res) => {
  try {
    const db = await connectToDb();
    console.log('req.user:', req.user);
    const userId = new ObjectId(req.user._id);
    const employer = await db.collection('Employer').findOne({ userID: userId });
    console.log('userId as ObjectId:', userId);
console.log('Looking for Employer with userID:', userId.toHexString());


    if (!employer) {
      return res.status(404).json({ success: false, message: 'Employer not found' });
    }

    const newInternship = {
      title: req.body.title,
      company: employer.company,
      location: req.body.location,
      duration: req.body.duration,
      stipend: req.body.stipend,
      description: req.body.description,
      requirements: req.body.requirements,
      employerId: userId,
      employerEmail: employer.email,
      verified: employer.verified,
      type: req.body.type,
      experience: req.body.experience,
      deadline: new Date(req.body.deadline)
    };


    const result = await db.collection('Internships').insertOne(newInternship);
    res.status(201).json({ success: true, internship: result.ops?.[0] ?? newInternship });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to create internship' });
  }
});

app.put('/api/internships/:id', authMiddleware, async (req, res) => {
  try {
    const db = await connectToDb();
    const internshipId = new ObjectId(req.params.id);

    const update = {
      $set: {
        title: req.body.title,
        location: req.body.location,
        duration: req.body.duration,
        stipend: req.body.stipend,
        description: req.body.description,
        requirements: req.body.requirements 
      }
    };

    const result = await db.collection('Internships').updateOne({ _id: internshipId }, update);
    res.status(200).json({ success: true, updated: result.modifiedCount > 0 });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to update internship' });
  }
});

app.delete('/api/internships/:id', authMiddleware, async (req, res) => {
  try {
    const db = await connectToDb();
    const internshipId = new ObjectId(req.params.id);

    const result = await db.collection('Internships').deleteOne({ _id: internshipId });
    res.status(200).json({ success: true, deleted: result.deletedCount > 0 });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to delete internship' });
  }
});


// GET /api/internships/:id/applications
// app.get('/api/internships/:id/applications', authMiddleware, async (req, res) => {
//   const { ObjectId } = require('mongodb');
//   const internshipId = req.params.id;

//   if (!ObjectId.isValid(internshipId)) {
//     return res.status(400).json({ success: false, message: 'Invalid internship ID' });
//   }

//   try {
//     const db = await connectToDb();

//     // Find all applications for this internship
//     const applications = await db.collection('Applications')
//       .find({ internshipID: internshipId })
//       .toArray();

//     // Enrich with student + user info
//     const enriched = await Promise.all(applications.map(async (app) => {
//       const student = await db.collection('Students').findOne({ userID: new ObjectId(app.studentID) });
//       const user = await db.collection('Users').findOne({ _id: new ObjectId(app.studentID) });

//       return {
//         applicationId: app._id,
//         studentId: app.studentID,
//         name: `${user?.fname ?? ''} ${user?.lname ?? ''}`.trim(),
//         email: user?.email ?? '',
//         school: student?.OrgName ?? '',
//         phone: student?.phone ?? '',
//         feedback: app.feedback,
//         description: app.description || '',
//         cv: app.cv,
//         coverLetter: app.coverLetter,
//         applicationDate: app.applicationDate
//       };
//     }));

//     res.status(200).json({ success: true, applications: enriched });
//   } catch (err) {
//     console.error('Error fetching applications:', err);
//     res.status(500).json({ success: false, message: 'Server error' });
//   }
// });

// PUT /api/applications/:id/feedback
// app.put('/api/applications/:id/feedback', authMiddleware, async (req, res) => {
//   const { ObjectId } = require('mongodb');
//   const applicationId = req.params.id;
//   const { feedback, description } = req.body;

//   if (!ObjectId.isValid(applicationId)) {
//     return res.status(400).json({ success: false, message: 'Invalid application ID' });
//   }

//   try {
//     const db = await connectToDb();

//     await db.collection('Applications').updateOne(
//       { _id: new ObjectId(applicationId) },
//       { $set: { feedback, description } }
//     );

//     res.status(200).json({ success: true, message: 'Feedback updated' });
//   } catch (err) {
//     console.error('Error updating feedback:', err);
//     res.status(500).json({ success: false, message: 'Update failed' });
//   }
// });

// In your backend (Node + Express + MongoDB)
app.get('/api/internships/:id/applications', authMiddleware, async (req, res) => {
  const internshipId = req.params.id;
  console.log(internshipId);
  const db = await connectToDb();

  const applications = await db.collection('Applications').aggregate([
    { $match: { internshipID: new ObjectId(internshipId) } },
    {
      $lookup: {
        from: 'users',
        localField: 'studentID',
        foreignField: '_id',
        as: 'user'
      }
    },
    { $unwind: '$user' },
    {
      $lookup: {
        from: 'Students',
        localField: 'studentID',
        foreignField: 'userID',
        as: 'student'
      }
    },
    { $unwind: '$student' },
    {
      $project: {
        applicationId: '$_id',
        name: { $concat: ['$user.fname', ' ', '$user.lname'] },
        email: '$user.email',
        phone: '$student.phone',
        school: '$student.OrgName',
        feedback: 1,
        description: 1,
        cv: 1,
        coverLetter: 1,
        applicationDate: 1
      }
    }
  ]).toArray();
  console.log("applications")
  console.log(applications)
  res.status(200).json({ applications });
});

app.put('/api/applications/:id/feedback', async (req, res) => {
  const { id } = req.params;
  const { feedback, description } = req.body;

  const db = await connectToDb();
  await db.collection('Applications').updateOne(
    { _id: new ObjectId(id) },
    { $set: { feedback, description } }
  );

  res.status(200).json({ message: 'Feedback updated' });
});

console.log("Loaded GROQ_API_KEY:", process.env.GROQ_API_KEY);

app.post('/api/ai-enhance-cv', async (req, res) => {
  const { cvText, jobDescription } = req.body;
  console.log('Loaded GROQ_API_KEY:', process.env.GROQ_API_KEY ? process.env.GROQ_API_KEY : '❌ Missing');

  if (!cvText) {
    return res.status(400).json({ error: 'cvText is required' });
  }

  const prompt = jobDescription
    ? `Revamp the following student CV to match the job description below:\n\nCV:\n${cvText}\n\nJob Description:\n${jobDescription}\n\nOutput a tailored, professional version of the CV.`
    : `Improve and polish the following student CV:\n\n${cvText}\n\nMake it more professional and impactful.`;

  try {
    const response = await axios.post(
      'https://api.groq.com/openai/v1/chat/completions',
      {
        model: 'meta-llama/llama-4-scout-17b-16e-instruct',
        messages: [
          { role: 'system', content: 'You are a professional resume writer for African university students.' },
          { role: 'user', content: prompt }
        ],
        temperature: 0.7
      },
      {
        headers: {
          'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    const result = response.data.choices[0].message.content;
    res.json({ enhancedCV: result });
  } catch (error) {
    console.error('Groq AI error:', error.response?.data || error.message);
    res.status(500).json({ error: 'AI enhancement failed' });
  }
});



// // Start the server
// app.listen(port, () => {
//     console.log(`Server running on http://localhost:${port}`);
// });



async function insertCareerOfficerManually() {
  const { ObjectId } = require('mongodb');
  // const bcrypt = require('bcrypt');
  const db = await connectToDb();

  const staffUserId = new ObjectId();
  const hashedPassword = await bcrypt.hash("123", 10); // change as needed

  // Insert into Users collection
  await db.collection('users').insertOne({
    _id: staffUserId,
    fname: "cyp",
    lname: "cyp",
    email: "cyprian.kamau@strathmore.edu",
    password: hashedPassword,
    role: "careerOfficer",
    verified: true,
    createdAt: new Date()
  });

  // Insert into CareerOffice collection
  await db.collection('careerOffice').insertOne({
    StaffID: "CO001",
    userID: staffUserId,
    Name: "Paul Macharia",
    OrgName: "Strathmore University",
    Phone: "0712345678",
    Email: "pmacharia@strathmore.edu",
    description: "Handles all student internship verification."
  });

  console.log("✅ Career Officer added successfully.");
  process.exit(); // stop server after insert
}

// view analytics
app.get('/api/applications/analytics', async (req, res) => {
  try {
    const db = await connectToDb(); // your existing DB connection helper
    const collection = db.collection('Applications');

    const pipeline = [
      {
        $group: {
          _id: "$feedback",
          count: { $sum: 1 }
        }
      }
    ];

    const results = await collection.aggregate(pipeline).toArray();

    // Optional: Convert results to a cleaner format
    const response = results.reduce((acc, curr) => {
      acc[curr._id] = curr.count;
      return acc;
    }, {});

    res.json(response);
  } catch (error) {
    console.error("Analytics fetch error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});
//verify organizations
app.get('/api/employers', async (req, res) => {
  try {
    const db = await connectToDb();
    const employers = await db.collection('Employer')
      .find({ company: { $exists: true } })
      .toArray();

    const employersWithStatus = employers.map(emp => {
      let status = 'Pending';
      if (emp.verified) status = 'Verified';
      else if (emp.reported) status = 'Reported';
      return { ...emp, status };
    });

    console.log("With status:", employersWithStatus); // Confirm here

    res.json(employersWithStatus);
  } catch (error) {
    console.error("Error fetching employers:", error);
    res.status(500).json({ message: "Failed to fetch employers." });
  }
});

// career officer's profile
app.get('/api/career-office/:staffId', async (req, res) => {
  const { userId } = req.params;
  try {
    const db = await connectToDb();
    const officer = await db.collection('careerOffice').findOne({ userID: userId });

    if (!officer) return res.status(404).json({ message: 'Officer not found' });

    res.json(officer);
  } catch (err) {
    console.error("Fetch officer error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

async function fixEmployerSchema() {
  try {
    const db = await connectToDb();
    const employerCollection = db.collection("Employer");

    const result = await employerCollection.updateMany(
      { verified: { $exists: false } },
      { $set: { verified: false } }
      
    );

    console.log(`✅ Updated ${result.modifiedCount} employers with verified: false`);
  } catch (error) {
    console.error("❌ Error updating employer schema:", error);
  }
}

fixEmployerSchema();


// handling the actual verification of employers
// ✅ Verify Employer
app.patch('/api/employers/:id/verify', async (req, res) => {
  const employerId = req.params.id;

  try {
    const db = await connectToDb();
    const employerCollection = db.collection("Employer");

    const result = await employerCollection.updateOne(
      { _id: new ObjectId(employerId) },
      {
        $set: {
          verified: true,
          reported: false,
          verificationDate: new Date()
        }
      }
    );

    if (result.modifiedCount === 1) {
      res.status(200).json({ message: "Employer verified successfully." });
    } else {
      res.status(404).json({ message: "Employer not found." });
    }
  } catch (error) {
    console.error("Error verifying employer:", error);
    res.status(500).json({ message: "Server error while verifying employer." });
  }
});

// ⚠️ Report Employer
app.post('/api/employers/:id/report', async (req, res) => {
  const employerId = req.params.id;

  try {
    const db = await connectToDb();
    const employerCollection = db.collection("Employer");

    const result = await employerCollection.updateOne(
      { _id: new ObjectId(employerId) },
      {
        $set: {
          verified: false,
          reported: true,
          reportReason: req.body.reason || "Flagged as suspicious",
          reportDate: new Date()
        }
      }
    );

    if (result.modifiedCount === 1) {
      res.status(200).json({ message: "Employer reported and verification removed." });
    } else {
      res.status(404).json({ message: "Employer not found." });
    }
  } catch (error) {
    console.error("Error reporting employer:", error);
    res.status(500).json({ message: "Server error while reporting employer." });
  }
});


// Update career officer's profile
app.put('/api/career-office/:staffId', async (req, res) => {
  const { staffId } = req.params;
  const { Name, OrgName, Phone, Email, description } = req.body;

  try {
    const db = await connectToDb();
    const result = await db.collection('careerOffice').updateOne(
      { StaffId: staffId },
      { $set: { Name, OrgName, Phone, Email, description } }
    );

    if (result.modifiedCount === 0) return res.status(404).json({ message: 'No changes made or officer not found' });

    res.json({ message: "Profile updated successfully" });
  } catch (err) {
    console.error("Update officer error:", err);
    res.status(500).json({ message: "Server error" });
  }
});
app.get('/api/internships', async (req, res) => {
  try {
    const db = await connectToDb();
    const internships = await db.collection("Internships").aggregate([
      {
        $lookup: {
          from: "Employer",
          localField: "employerId",
          foreignField: "_id",
          as: "employer"
        }
      },
      { $unwind: "$employer" }, // Flatten employer array
      { $match: { "employer.verified": true } }, // Show only verified
      { $sort: { postedAt: -1 } } // Optional: newest first
    ]).toArray();

    res.json(internships);
  } catch (err) {
    console.error("Error fetching internships:", err);
    res.status(500).json({ message: "Server error fetching internships" });
  }
});
//update admin profile
app.get('/api/career-officers/by-user/:userId', authMiddleware, async (req, res) => {
  const userId = req.params.userId;
  if (!ObjectId.isValid(userId)) {
    return res.status(400).json({ success: false, message: 'Invalid user ID format' });
  }

  const db = await connectToDb();
  const officer = await db.collection('careerOffice').findOne({ userID: new ObjectId(userId) });
  const user = await db.collection('users').findOne({ _id: new ObjectId(userId) });

  if (!officer || !user) {
    return res.status(404).json({ success: false, message: 'Career officer or user not found' });
  }

  res.json({
    success: true,
    data: {
      ...officer,
      fname: user.fname,
      lname: user.lname,
      email: user.email
    }
  });
});


  // PUT update career officer profile (excluding email)
 app.put('/api/career-officers/:id', authMiddleware, async (req, res) => {
  const officerId = req.params.id;
  if (!ObjectId.isValid(officerId)) {
    return res.status(400).json({ success: false, message: 'Invalid officer ID' });
  }

  const {
    fname,
    lname,
    OrgName,
    Phone,
    description
  } = req.body;

  if (!OrgName) {
    return res.status(400).json({
      success: false,
      message: 'Organization Name is required',
      missingFields: { required: ['OrgName'] }
    });
  }

  const db = await connectToDb();

  const officer = await db.collection('careerOffice').findOne({ _id: new ObjectId(officerId) });
  if (!officer) {
    return res.status(404).json({ success: false, message: 'Career officer not found' });
  }

  // Update career officer collection
  await db.collection('careerOffice').updateOne(
    { _id: new ObjectId(officerId) },
    {
      $set: {
        OrgName,
        Phone,
        description,
        updatedAt: new Date()
      }
    }
  );

  // Update the user's fname and lname only
  await db.collection('users').updateOne(
    { _id: officer.userID },
    {
      $set: {
        fname,
        lname
      }
    }
  );

  res.json({ success: true, message: 'Career officer profile updated successfully' });
});


//  career dashboard stats
app.get('/api/dashboard-stats', async (req, res) => {
  try {
    const db = await connectToDb();

    const verifiedOrgsCount = await db.collection('Employer').countDocuments({ verified: true });
    const rejectedOrgsCount = await db.collection('Employer').countDocuments({ verified: false });
    const internshipsCount = await db.collection('Internships').countDocuments({}); // or add filters if needed
    const applicationsCount = await db.collection('Applications').countDocuments({}); // assuming this collection exists

    res.json({
      verifiedOrgs: verifiedOrgsCount,
      rejectedOrgs: rejectedOrgsCount,
      internships: internshipsCount,
      applications: applicationsCount,
    });
  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    res.status(500).json({ message: 'Failed to fetch dashboard stats' });
  }
});
// GET /api/analytics/user-roles
app.get('/api/analytics/user-roles', authMiddleware, async (req, res) => {
  const db = await connectToDb();

  const userCounts = await db.collection('users').aggregate([
    { $group: { _id: '$role', count: { $sum: 1 } } }
  ]).toArray();

  res.json({ success: true, data: userCounts });
});

// for the alert section
app.get('/api/alerts', async (req, res) => {
  try {
    const db = await connectToDb();

    const unverified = await db.collection("Employer")
      .find({ verified: false }) // no sort
      .limit(5)
      .toArray();

    const alerts = unverified.map(org => ({
      type: "organization",
      message: `New organization "${org.company}" pending verification`,
      timestamp: org.createdAt || new Date()
    }));

    res.json(alerts);
  } catch (err) {
    console.error("Error fetching alerts:", err);
    res.status(500).json({ message: "Server error fetching alerts" });
  }
});
//forgot password
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  const db = await connectToDb();
  const user = await db.collection('Users').findOne({ email });
  if (!user) return res.status(404).json({ message: "Email not found" });

  const token = crypto.randomBytes(32).toString("hex");
  const expiry = new Date(Date.now() + 3600000); // 1 hour

  await db.collection('PasswordResets').insertOne({
    userId: user._id,
    token,
    expiresAt: expiry
  });

  const resetLink = `http://localhost:3000/reset-password/${token}`;
  // Send using nodemailer or Mailtrap
  await sendMail(user.email, "Reset Your Password", `Click to reset: ${resetLink}`);

  res.json({ message: "Reset link sent" });
});
// Reset password endpoint
app.post('/api/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const db = await connectToDb();
    const resetEntry = await db.collection('PasswordResets').findOne({ token });

    if (!resetEntry || resetEntry.expiresAt < new Date()) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.collection('users').updateOne(
      { _id: new ObjectId(resetEntry.userId) },
      { $set: { password: hashedPassword } }
    );

    await db.collection('PasswordResets').deleteOne({ token });
console.log("Password reset successful for token:", token);

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('Reset error:', err);
    res.status(500).json({ message: 'Server error resetting password' });
  }
});

// Add a comment for a specific internship


app.post('/api/comments', async (req, res) => {
  const { internshipId, studentId, comment, rating } = req.body;

  if (!internshipId || !studentId || !comment) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  if (!ObjectId.isValid(internshipId) || !ObjectId.isValid(studentId)) {
    return res.status(400).json({ error: 'Invalid internship or student ID' });
  }

  try {
    const db = await connectToDb();
    const Comments = db.collection('Comments');
    const Applications = db.collection('Applications');

    const internshipObjectId = new ObjectId(internshipId);
    const studentObjectId = new ObjectId(studentId);

    const hasApplied = await Applications.findOne({
      internshipID: internshipObjectId,
      studentID: studentObjectId,
    });

    if (!hasApplied) {
      return res.status(403).json({
        error: 'You can only comment after applying for an internship.',
      });
    }

    const existing = await Comments.findOne({
      internshipId: internshipObjectId,
      studentId: studentObjectId,
    });

    if (existing) {
      return res.status(400).json({ error: 'You have already commented.' });
    }

    const newComment = {
      internshipId: internshipObjectId,
      studentId: studentObjectId,
      comment,
      rating: rating || null,
      createdAt: new Date(),
    };

    const result = await Comments.insertOne(newComment);
    res.status(201).json({ success: true, commentId: result.insertedId });

  } catch (err) {
    console.error('Comment insert error:', err);
    res.status(500).json({ error: 'Server error adding comment' });
  }
});


// Get all comments made by a specific student
app.get('/api/comments/:studentId', async (req, res) => {
  const { studentId } = req.params;

  if (!ObjectId.isValid(studentId)) {
    return res.status(400).json({ error: 'Invalid student ID' });
  }

  try {
    const db = await connectToDb();
    const Comments = db.collection('Comments');

    const comments = await Comments.find({
      studentId: new ObjectId(studentId),
    }).toArray();

    res.json(comments);
  } catch (err) {
    console.error('Error fetching student comments:', err);
    res.status(500).json({ error: 'Server error fetching comments' });
  }
});

// Get a single comment by its commentId
app.get('/api/comments/single/:commentId', async (req, res) => {
  const { commentId } = req.params;

  if (!ObjectId.isValid(commentId)) {
    return res.status(400).json({ error: 'Invalid comment ID' });
  }

  try {
    const db = await connectToDb();
    const Comments = db.collection('Comments');

    const comment = await Comments.findOne({ _id: new ObjectId(commentId) });

    if (!comment) {
      return res.status(404).json({ error: 'Comment not found' });
    }

    res.json({ success: true, data: comment });
  } catch (err) {
    console.error('Error fetching comment:', err);
    res.status(500).json({ error: 'Server error fetching comment' });
  }
});

// Update an existing comment
// Update a comment by its commentId
app.put('/api/comments/:commentId', async (req, res) => {
  const { comment, rating } = req.body;
  const { commentId } = req.params;

  if (!ObjectId.isValid(commentId)) {
    return res.status(400).json({ error: 'Invalid comment ID' });
  }

  try {
    const db = await connectToDb();
    const Comments = db.collection('Comments');

    const result = await Comments.updateOne(
      { _id: new ObjectId(commentId) },
      {
        $set: {
          comment,
          rating,
          updatedAt: new Date(),
        },
      }
    );

    if (result.modifiedCount === 1) {
      res.json({ success: true });
    } else {
      res.status(404).json({ error: 'Comment not found or not updated' });
    }
  } catch (err) {
    console.error('Update error:', err);
    res.status(500).json({ error: 'Server error updating comment' });
  }
});


app.delete('/api/comments/:commentId', async (req, res) => {
  const { commentId } = req.params;

  if (!ObjectId.isValid(commentId)) {
    return res.status(400).json({ error: 'Invalid comment ID' });
  }

  try {
    const db = await connectToDb();
    const Comments = db.collection('Comments');

    const result = await Comments.deleteOne({ _id: new ObjectId(commentId) });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Comment not found' });
    }

    res.json({ success: true, message: 'Comment deleted successfully' });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Server error deleting comment' });
  }
});

// Check if a student has applied to any internship
app.get('/api/applications/check/:studentId', async (req, res) => {
  const { studentId } = req.params;

  if (!ObjectId.isValid(studentId)) {
    return res.status(400).json({ error: 'Invalid student ID' });
  }

  try {
    const db = await connectToDb();
    const Applications = db.collection('Applications');

    const application = await Applications.findOne({
      studentID: new ObjectId(studentId),
    });

    if (application) {
      res.json({
        hasApplied: true,
        internshipId: application.internshipID,
      });
    } else {
      res.json({ hasApplied: false });
    }
  } catch (err) {
    console.error('Application check error:', err);
    res.status(500).json({ error: 'Server error checking applications' });
  }
});


// Get all comments (for admin moderation)
app.get('/api/comments', async (req, res) => {
  try {
    const db = await connectToDb();

    const comments = await db.collection("Comments").aggregate([
      {
        $lookup: {
          from: "Students",
          localField: "studentId",       // from Comments (ObjectId)
          foreignField: "userID",           // from Students (_id)
          as: "studentInfo"
        }
      },
      {
        $unwind: {
          path: "$studentInfo",
          preserveNullAndEmptyArrays: true
        }
      },
      {
        $project: {
          comment: 1,
          rating: 1,
          internshipId: 1,
          createdAt: 1,
          studentId: 1,
          studentID: "$studentInfo.studentID" // ✅ pull studentID string field from Students
        }
      }
    ]).toArray();

    res.json({ success: true, data: comments });
  } catch (err) {
    console.error('Error fetching comments:', err);
    res.status(500).json({ success: false, error: 'Server error fetching comments' });
  }
});


// admin delete comment by commentId
app.delete('/api/comments/:commentId', async (req, res) => {
  try {
    const db = await connectToDb();
    const result = await db.collection("Comments").deleteOne({ _id: new ObjectId(req.params.commentId) });
    if (result.deletedCount === 1) {
      res.json({ success: true, message: 'Comment deleted successfully' });
    } else {
      res.status(404).json({ success: false, message: 'Comment not found' });
    }
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ success: false, message: 'Server error deleting comment' });
  }
});
//admin to view all users
app.get('/api/users', async (req, res) => {
  try {
    const db = await connectToDb();
    const users = await db.collection("users")
      .find({ role: { $ne: "careerOfficer" } })
      .project({ fname: 1, lname: 1, email: 1, role: 1 })
      .toArray();

    res.json({ success: true, data: users });
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ success: false, message: "Server error fetching users" });
  }
});
//admin to delete all users
app.delete('/api/users/:userId', async (req, res) => {
  try {
    const db = await connectToDb();
    const userId = req.params.userId;

    const result = await db.collection("users").deleteOne({ _id: new ObjectId(userId) });

    if (result.deletedCount === 1) {
      res.json({ success: true, message: "User deleted successfully" });
    } else {
      res.status(404).json({ success: false, message: "User not found" });
    }
  } catch (error) {
    console.error("Delete user error:", error);
    res.status(500).json({ success: false, message: "Server error deleting user" });
  }
});


// Start the server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});



// async  insertCareerOfficerManually() {
//   const { ObjectId } = require('mongodb');
//   // const bcrypt = require('bcrypt');
//   const db = await connectToDb();

//   const staffUserId = new ObjectId();
//   const hashedPassword = await bcrypt.hash("123", 10); // change as needed

//   // Insert into Users collection
//   await db.collection('users').insertOne({
//     _id: staffUserId,
//     fname: "cyp",
//     lname: "cyp",
//     email: "cyprian.kamau@strathmore.edu",
//     password: hashedPassword,
//     role: "careerOfficer",
//     verified: true,
//     createdAt: new Date()
//   });

//   // Insert into CareerOffice collection
//   await db.collection('careerOffice').insertOne({
//     StaffID: "CO001",
//     userID: staffUserId,
//     Name: "Paul Macharia",
//     OrgName: "Strathmore University",
//     Phone: "0712345678",
//     Email: "pmacharia@strathmore.edu",
//     description: "Handles all student internship verification."
//   });

//   console.log("✅ Career Officer added successfully.");
//   process.exit(); // stop server after insert
// }
// view analytics



// fixing some issues with the Internships schema
// async function linkInternshipsToEmployers() {
//   try {
//     const db = await connectToDb();
//     const internshipCollection = db.collection("Internships");
//     const employerCollection = db.collection("Employer");

//     const internships = await internshipCollection.find().toArray();

//     for (const internship of internships) {
//       const employerEmail = internship.employerEmail;

//       if (!employerEmail) {
//         console.warn(`⚠️ Skipping internship ${internship._id}: No employerEmail found.`);
//         continue;
//       }

//       const employer = await employerCollection.findOne({ email: employerEmail });

//       if (!employer) {
//         console.warn(`❌ No employer found for internship email: ${employerEmail}`);
//         continue;
//       }

//       const updateResult = await internshipCollection.updateOne(
//         { _id: internship._id },
//         { $set: { employerId: employer._id } }
//       );

//       console.log(`✅ Linked internship ${internship._id} to employer ${employer._id}`);
//     }

//     console.log("🎉 Linking complete.");
//   } catch (error) {
//     console.error("❌ Error linking internships to employers:", error);
//   }
// }

// linkInternshipsToEmployers();

// GET internships with employer data


// ⚠️ Un-comment the line below ONLY when you want to insert the career officer
//  insertCareerOfficerManually();

// async function seedDatabase() {
//   try {
//     const db = client.db('Hustle-db'); // your DB name

//     console.log('🌱 Seeding database...');


//     const passwordHash = await bcrypt.hash('password123', 10);

//     const userInserts = [
//       { email: 'student1@example.com', role: 'student', password: passwordHash },
//       { email: 'employer1@example.com', role: 'employer', password: passwordHash },
//       { email: 'officer1@example.com', role: 'careerOfficer', password: passwordHash }
//     ];
//     const users = await db.collection('users').insertMany(userInserts);
//     const [studentUserId, employerUserId, officerUserId] = Object.values(users.insertedIds);

//     await db.collection('Students').insertMany([
//       {
//         _id: studentUserId,
//         fname: 'Alice',
//         lname: 'Wambui',
//         email: 'student1@example.com',
//         studentID: 'S123456',
//         dob: '2001-05-21',
//         phone: '0700111222',
//         course: 'BSc Computer Science',
//         yearOfStudy: '3',
//         OrgName: 'Strathmore University',
//         description: 'Enthusiastic student seeking internships',
//         createdAt: new Date(),
//         updatedAt: new Date()
//       },
//       {
//         fname: 'Brian',
//         lname: 'Kamau',
//         email: 'student2@example.com',
//         studentID: 'S654321',
//         dob: '2002-03-15',
//         phone: '0700333444',
//         course: 'BBIT',
//         yearOfStudy: '2',
//         OrgName: 'Strathmore University',
//         description: 'Looking for finance tech opportunities'
//       },
//       {
//         fname: 'Cynthia',
//         lname: 'Otieno',
//         email: 'student3@example.com',
//         studentID: 'S777888',
//         dob: '2000-12-01',
//         phone: '0700555666',
//         course: 'BSc Informatics',
//         yearOfStudy: '4',
//         OrgName: 'Strathmore University',
//         description: 'Skilled in React and backend APIs'
//       }
//     ]);

//     await db.collection('Employer').insertMany([
//       {
//         _id: employerUserId,
//         company: 'TechSoft Ltd.',
//         email: 'employer1@example.com',
//         website: 'https://techsoft.co.ke',
//         contact: '0711222333',
//         description: 'A software development firm based in Nairobi',
//         createdAt: new Date()
//       },
//       {
//         company: 'DataWorks Kenya',
//         email: 'employer2@example.com',
//         website: 'https://dataworks.co.ke',
//         contact: '0722333444',
//         description: 'We deal with big data analysis and cloud services.'
//       },
//       {
//         company: 'GreenApps',
//         email: 'employer3@example.com',
//         website: 'https://greenapps.org',
//         contact: '0733444555',
//         description: 'Sustainable tech and green innovation'
//       }
//     ]);

//     await db.collection('CareerOfficers').insertMany([
//       {
//         _id: officerUserId,
//         fname: 'Jane',
//         lname: 'Mugo',
//         email: 'officer1@example.com',
//         phone: '0711777888',
//         department: 'Career Services',
//         createdAt: new Date()
//       },
//       {
//         fname: 'Mark',
//         lname: 'Odhiambo',
//         email: 'officer2@example.com',
//         phone: '0722888999',
//         department: 'Student Affairs'
//       },
//       {
//         fname: 'Linda',
//         lname: 'Njuguna',
//         email: 'officer3@example.com',
//         phone: '0733999000',
//         department: 'Alumni Relations'
//       }
//     ]);

//     const internships = await db.collection('Internships').insertMany([
//       {
//         title: 'Frontend Developer Intern',
//         employerId: employerUserId,
//         location: 'Remote',
//         deadline: '2025-08-01',
//         description: 'Work on React interfaces for internal tools.'
//       },
//       {
//         title: 'Data Analyst Intern',
//         employerId: employerUserId,
//         location: 'Nairobi',
//         deadline: '2025-07-15',
//         description: 'Analyze and visualize company performance data.'
//       },
//       {
//         title: 'DevOps Intern',
//         employerId: employerUserId,
//         location: 'Hybrid',
//         deadline: '2025-09-10',
//         description: 'Assist with CI/CD pipelines and monitoring tools.'
//       }
//     ]);

//     const internshipIds = Object.values(internships.insertedIds);

//     await db.collection('Applications').insertMany([
//       {
//         studentId: studentUserId,
//         internshipId: internshipIds[0],
//         status: 'pending',
//         appliedAt: new Date()
//       },
//       {
//         studentId: studentUserId,
//         internshipId: internshipIds[1],
//         status: 'reviewed',
//         appliedAt: new Date()
//       },
//       {
//         studentId: studentUserId,
//         internshipId: internshipIds[2],
//         status: 'approved',
//         appliedAt: new Date()
//       }
//     ]);

//     await db.collection('Comments').insertMany([
//       {
//         internshipId: internshipIds[0],
//         studentId: studentUserId,
//         comment: 'Is this internship remote-friendly?',
//         createdAt: new Date()
//       },
//       {
//         internshipId: internshipIds[1],
//         studentId: studentUserId,
//         comment: 'What are the required skills?',
//         createdAt: new Date()
//       },
//       {
//         internshipId: internshipIds[2],
//         studentId: studentUserId,
//         comment: 'How many hours per week?',
//         createdAt: new Date()
//       }
//     ]);

//     await db.collection('Feedback').insertMany([
//       {
//         from: 'employer1@example.com',
//         to: 'student1@example.com',
//         comment: 'Strong resume and good communication.',
//         rating: 4
//       },
//       {
//         from: 'employer1@example.com',
//         to: 'student1@example.com',
//         comment: 'Needs improvement in Git.',
//         rating: 3
//       },
//       {
//         from: 'officer1@example.com',
//         to: 'student1@example.com',
//         comment: 'Keep working on your portfolio!',
//         rating: 5
//       }
//     ]);

//     console.log('✅ Database seeded with sample data.');
//   } catch (err) {
//     console.error('❌ Error during seeding:', err);
//   } finally {
//     await client.close();
//   }
// }

// seedDatabase()