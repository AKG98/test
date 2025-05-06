import express from 'express';
import { config } from 'dotenv';
import cookieParser from 'cookie-parser';
import DBConnection from './config/connectDB';
import authRoutes from './routes/auth.routes';
import taskRoutes from './routes/task.route';

config(); 
const app = express();
const PORT = process.env.PORT || 5000; 

// Middleware
app.use(express.json()); 
app.use(express.urlencoded({ extended: true })); 
app.use(cookieParser()); 

// Database connection
DBConnection(); 

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/tasks', taskRoutes);

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
}
);



