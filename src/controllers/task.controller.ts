import { Request, Response } from "express";
import TaskModel from "../models/task.model";
import mongoose from "mongoose";

// Define the shape of the request user
interface IRequestUser extends Request {
  user?: { _id: string };
  userId?: string; // Optional userId property


}

// Create a new task
export async function createTask(req: Request, res: Response): Promise<void> {
  try {
    const task = new TaskModel(req.body);
    const savedTask = await task.save();

    res.status(201).json({
      success: true,
      message: "Task created successfully",
      data: savedTask,
    });
  } catch (error) {
    if (error instanceof mongoose.Error.ValidationError) {
      res.status(400).json({
        success: false,
        message: "Validation error",
        errors: error.errors,
      });
    } else {
      res.status(500).json({
        success: false,
        message: "Internal server error",
      });
    }
  }
}

// Get all tasks - requires authentication
export async function getTasks(
  req: IRequestUser,
  res: Response
): Promise<void> {
  const { userId } = req.body;
  try {
    const page = parseInt(req.query.page as string || "1"); 
    const limit = parseInt(req.query.limit as string || "10"); 
    const skip = (page - 1) * limit;

    const tasks = await TaskModel.find({ user: userId })
      .skip(skip)
      .limit(limit)
    const total = await TaskModel.countDocuments();

    res.status(200).json({
      success: true,
      page,
      totalPages: Math.ceil(total / limit),
      totalTasks: total,
      tasks,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}

// Update a task
export async function updateTask(req: Request, res: Response): Promise<void> {
  try {
    const taskId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(taskId)) {
      res.status(400).json({ success: false, message: "Invalid task ID" });
      return;
    }

    const updatedTask = await TaskModel.findByIdAndUpdate(taskId, req.body, {
      new: true,
      runValidators: true,
    });

    if (!updatedTask) {
      res.status(404).json({ success: false, message: "Task not found" });
      return;
    }

    res.status(200).json({
      success: true,
      message: "Task updated successfully",
      data: updatedTask,
    });
  } catch (error) {
    if (error instanceof mongoose.Error.ValidationError) {
      res.status(400).json({
        success: false,
        message: "Validation error",
        errors: error.errors,
      });
    } else {
      res.status(500).json({
        success: false,
        message: "Internal server error",
      });
    }
  }
}

// Delete a task
export async function deleteTask(req: Request, res: Response): Promise<void> {
  try {
    const taskId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(taskId)) {
      res.status(400).json({ success: false, message: "Invalid task ID" });
      return;
    }

    const deletedTask = await TaskModel.findByIdAndDelete(taskId);

    if (!deletedTask) {
      res.status(404).json({ success: false, message: "Task not found" });
      return;
    }

    res.status(200).json({
      success: true,
      message: "Task deleted successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}
