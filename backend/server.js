// server.js
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const validator = require('validator');
const xss = require('xss');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(helmet());
// Replace the existing CORS configuration with this:
app.use(cors({
    origin: [
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'http://[::1]:3000',
        process.env.FRONTEND_URL || 'http://localhost:3000'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const contactLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: {
        error: 'Too many contact form submissions, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/portfolio', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// Contact Message Schema
const contactSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true,
        maxlength: 100
    },
    email: {
        type: String,
        required: true,
        trim: true,
        lowercase: true,
        validate: [validator.isEmail, 'Invalid email address']
    },
    subject: {
        type: String,
        required: true,
        enum: ['collaboration', 'job', 'project', 'research', 'consulting', 'other']
    },
    message: {
        type: String,
        required: true,
        trim: true,
        minlength: 10,
        maxlength: 2000
    },
    ipAddress: String,
    userAgent: String,
    createdAt: {
        type: Date,
        default: Date.now
    },
    status: {
        type: String,
        enum: ['new', 'read', 'replied'],
        default: 'new'
    }
});

const Contact = mongoose.model('Contact', contactSchema);

// Email Configuration
const transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE || 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS // Use App Password for Gmail
    }
});

// Verify email configuration
transporter.verify((error, success) => {
    if (error) {
        console.error('❌ Email configuration error:', error);
    } else {
        console.log('✅ Email server ready');
    }
});

// Utility Functions
const sanitizeInput = (input) => {
    return xss(input.trim());
};

const validateContactData = (data) => {
    const errors = {};

    // Name validation
    if (!data.name || data.name.trim().length < 2) {
        errors.name = 'Name must be at least 2 characters long';
    }

    // Email validation
    if (!data.email || !validator.isEmail(data.email)) {
        errors.email = 'Please provide a valid email address';
    }

    // Subject validation
    const validSubjects = ['collaboration', 'job', 'project', 'research', 'consulting', 'other'];
    if (!data.subject || !validSubjects.includes(data.subject)) {
        errors.subject = 'Please select a valid subject';
    }

    // Message validation
    if (!data.message || data.message.trim().length < 10) {
        errors.message = 'Message must be at least 10 characters long';
    } else if (data.message.trim().length > 2000) {
        errors.message = 'Message must be less than 2000 characters';
    }

    return {
        isValid: Object.keys(errors).length === 0,
        errors
    };
};

const sendEmailNotification = async (contactData) => {
    const subjectMap = {
        collaboration: 'Collaboration Opportunity',
        job: 'Job Opportunity',
        project: 'Project Discussion',
        research: 'Research Collaboration',
        consulting: 'Consulting Services',
        other: 'General Inquiry'
    };

    const emailSubject = `New Contact Form Submission: ${subjectMap[contactData.subject]}`;
    
    const emailHTML = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #f8fafc; padding: 20px; border-radius: 10px;">
            <div style="background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #06b6d4 100%); padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 20px;">
                <h1 style="color: white; margin: 0; font-size: 24px;">New Portfolio Contact</h1>
            </div>
            
            <div style="background: white; padding: 30px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1);">
                <h2 style="color: #1e293b; margin-bottom: 20px; border-bottom: 2px solid #6366f1; padding-bottom: 10px;">Contact Details</h2>
                
                <div style="margin-bottom: 15px;">
                    <strong style="color: #6366f1;">Name:</strong> 
                    <span style="color: #1e293b;">${contactData.name}</span>
                </div>
                
                <div style="margin-bottom: 15px;">
                    <strong style="color: #6366f1;">Email:</strong> 
                    <a href="mailto:${contactData.email}" style="color: #06b6d4; text-decoration: none;">${contactData.email}</a>
                </div>
                
                <div style="margin-bottom: 15px;">
                    <strong style="color: #6366f1;">Subject:</strong> 
                    <span style="color: #1e293b;">${subjectMap[contactData.subject]}</span>
                </div>
                
                <div style="margin-bottom: 20px;">
                    <strong style="color: #6366f1;">Message:</strong>
                    <div style="background: #f1f5f9; padding: 15px; border-radius: 8px; margin-top: 8px; color: #1e293b; line-height: 1.6;">
                        ${contactData.message.replace(/\n/g, '<br>')}
                    </div>
                </div>
                
                <div style="border-top: 1px solid #e2e8f0; padding-top: 15px; font-size: 12px; color: #64748b;">
                    <p><strong>Received:</strong> ${new Date().toLocaleString()}</p>
                    <p><strong>IP Address:</strong> ${contactData.ipAddress}</p>
                </div>
            </div>
            
            <div style="text-align: center; margin-top: 20px; color: #64748b; font-size: 12px;">
                <p>This message was sent through your portfolio contact form.</p>
            </div>
        </div>
    `;

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: process.env.NOTIFICATION_EMAIL || process.env.EMAIL_USER,
        subject: emailSubject,
        html: emailHTML,
        replyTo: contactData.email
    };

    return transporter.sendMail(mailOptions);
};

const sendAutoReply = async (contactData) => {
    const autoReplyHTML = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #f8fafc; padding: 20px; border-radius: 10px;">
            <div style="background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #06b6d4 100%); padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 20px;">
                <h1 style="color: white; margin: 0; font-size: 24px;">Thank You for Reaching Out!</h1>
            </div>
            
            <div style="background: white; padding: 30px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1);">
                <p style="color: #1e293b; font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
                    Hi <strong>${contactData.name}</strong>,
                </p>
                
                <p style="color: #1e293b; font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
                    Thank you for your interest in my work! I've received your message about <strong>${contactData.subject}</strong> and I'm excited to learn more about your project.
                </p>
                
                <p style="color: #1e293b; font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
                    I typically respond to all inquiries within 24-48 hours. In the meantime, feel free to check out my latest projects on GitHub or connect with me on LinkedIn.
                </p>
                
                <div style="background: #f1f5f9; padding: 20px; border-radius: 10px; margin: 20px 0;">
                    <h3 style="color: #6366f1; margin-bottom: 15px;">Your Message Summary:</h3>
                    <p style="color: #64748b; font-style: italic;">"${contactData.message.substring(0, 150)}${contactData.message.length > 150 ? '...' : ''}"</p>
                </div>
                
                <p style="color: #1e293b; font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
                    Looking forward to our conversation!
                </p>
                
                <p style="color: #1e293b; font-size: 16px; line-height: 1.6;">
                    Best regards,<br>
                    <strong style="color: #6366f1;">Nazneen Aktar</strong><br>
                    <span style="color: #64748b;">Full Stack Developer & Data Scientist</span>
                </p>
            </div>
            
            <div style="text-align: center; margin-top: 20px;">
                <a href="https://github.com/nazneenaktar" style="display: inline-block; margin: 0 10px; color: #6366f1; text-decoration: none;">
                    🔗 GitHub
                </a>
                <a href="https://linkedin.com/in/nazneenaktar" style="display: inline-block; margin: 0 10px; color: #6366f1; text-decoration: none;">
                    🔗 LinkedIn
                </a>
            </div>
        </div>
    `;

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: contactData.email,
        subject: 'Thank you for reaching out - Nazneen Aktar',
        html: autoReplyHTML
    };

    return transporter.sendMail(mailOptions);
};

// Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Contact form submission
app.post('/api/contact', contactLimiter, async (req, res) => {
    try {
        // Sanitize input data
        const sanitizedData = {
            name: sanitizeInput(req.body.name),
            email: sanitizeInput(req.body.email),
            subject: sanitizeInput(req.body.subject),
            message: sanitizeInput(req.body.message)
        };

        // Validate data
        const validation = validateContactData(sanitizedData);
        if (!validation.isValid) {
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: validation.errors
            });
        }

        // Prepare contact data
        const contactData = {
            ...sanitizedData,
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent')
        };

        // Save to database
        const contact = new Contact(contactData);
        await contact.save();

        // Send email notifications
        const emailPromises = [
            sendEmailNotification(contactData)
        ];

        // Send auto-reply if enabled
        if (process.env.SEND_AUTO_REPLY === 'true') {
            emailPromises.push(sendAutoReply(contactData));
        }

        await Promise.all(emailPromises);

        console.log(`✅ New contact submission from ${contactData.email}`);

        res.status(200).json({
            success: true,
            message: 'Thank you! Your message has been sent successfully.',
            id: contact._id
        });

    } catch (error) {
        console.error('❌ Contact form error:', error);
        
        // Check if it's a validation error
        if (error.name === 'ValidationError') {
            const validationErrors = {};
            Object.keys(error.errors).forEach(key => {
                validationErrors[key] = error.errors[key].message;
            });
            
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: validationErrors
            });
        }

        res.status(500).json({
            success: false,
            message: 'Server error. Please try again later.'
        });
    }
});

// Get all contacts (admin endpoint)
app.get('/api/contacts', async (req, res) => {
    try {
        // Simple auth check (replace with proper authentication)
        const authKey = req.headers.authorization;
        if (authKey !== `Bearer ${process.env.ADMIN_KEY}`) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const contacts = await Contact.find()
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .select('-ipAddress -userAgent'); // Hide sensitive data

        const total = await Contact.countDocuments();

        res.json({
            success: true,
            data: contacts,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('❌ Error fetching contacts:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Update contact status (admin endpoint)
app.patch('/api/contacts/:id/status', async (req, res) => {
    try {
        const authKey = req.headers.authorization;
        if (authKey !== `Bearer ${process.env.ADMIN_KEY}`) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const { status } = req.body;
        if (!['new', 'read', 'replied'].includes(status)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid status'
            });
        }

        const contact = await Contact.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true }
        );

        if (!contact) {
            return res.status(404).json({
                success: false,
                message: 'Contact not found'
            });
        }

        res.json({
            success: true,
            data: contact
        });
    } catch (error) {
        console.error('❌ Error updating contact:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Portfolio stats endpoint
app.get('/api/stats', async (req, res) => {
    try {
        const totalContacts = await Contact.countDocuments();
        const newContacts = await Contact.countDocuments({ status: 'new' });
        const thisMonth = await Contact.countDocuments({
            createdAt: {
                $gte: new Date(new Date().getFullYear(), new Date().getMonth(), 1)
            }
        });

        res.json({
            success: true,
            data: {
                totalContacts,
                newContacts,
                contactsThisMonth: thisMonth,
                serverUptime: process.uptime()
            }
        });
    } catch (error) {
        console.error('❌ Error fetching stats:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('❌ Unhandled error:', err);
    res.status(500).json({
        success: false,
        message: 'Internal server error'
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'Endpoint not found'
    });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('🔄 SIGTERM received, shutting down gracefully...');
    await mongoose.connection.close();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('🔄 SIGINT received, shutting down gracefully...');
    await mongoose.connection.close();
    process.exit(0);
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📧 Email service: ${process.env.EMAIL_SERVICE || 'gmail'}`);
    console.log(`🗄️  Database: ${process.env.MONGODB_URI ? 'Remote MongoDB' : 'Local MongoDB'}`);
});