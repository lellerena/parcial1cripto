import express from "express";
import { getMessages, postMessage } from "../controllers/chatController";

const router = express.Router();

router.get("/", getMessages);
router.post("/", postMessage);

export default router;
