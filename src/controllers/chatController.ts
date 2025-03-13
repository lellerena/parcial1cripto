import { Request, Response } from "express";
import { Message } from "../models/Message";

const messages: Message[] = [];

export const getMessages = (req: Request, res: Response) => {
  res.json(messages);
};

export const postMessage = (req: Request, res: Response) => {
  const { user, text } = req.body;
  if (!user || !text) {
    res.status(400).json({ error: "Faltan datos" });
    return;
  }

  const newMessage: Message = { user, text, timestamp: Date.now() };
  messages.push(newMessage);

  res.status(201).json(newMessage);
};
