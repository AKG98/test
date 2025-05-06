import { Schema,model } from "mongoose";


// Define intreface for Task
export interface Task {
    title: string;
    description: string;
    dueDate: Date;
    status: "Pending" | "In Progress" | "Completed";
    user: string;
}


const TaskSchema = new Schema({
    title: {
        type: String,
        required: true,
    },
    description: {
        type: String,
        required: true,
    },
    dueDate: {
        type: Date,
        required: true,
    },
    status:{
        type: String,
        required: true,
        enum: ["Pending", "In Progress", "Completed"],
    },
    user: {
        type: Schema.Types.ObjectId,
        ref: "User",
        required: true,
    },
    },{timestamps: true});

const TaskModel = model("Tasks", TaskSchema);
export default TaskModel;