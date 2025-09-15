import axios from "axios";
import Chat from "../models/Chat.js";
import User from "../models/User.js";
import imagekit from "../configs/imageKit.js";
import openai from "../configs/openai.js";


// Text-based AI chat message controller
export const textMessageController = async (req, res) => {
    try {
        const userId = req.user._id;

        // check user credits
        if(req.user.credits < 1) {
            return res.json({ success: false, message: "You don't have enough credits to use this feature" });
        }

        const { chatId, prompt } = req.body;

        const chat = await Chat.findOne({ userId, _id: chatId });
        chat.messages.push({ role: "user", content: prompt, timestamp: Date.now(), isImage: false });

        const { choices } = await openai.chat.completions.create({
        model: "gemini-2.5-flash",
        messages: [
            {
                role: "user",
                content: prompt,
            },
        ],
    });

    const reply = {
        ...choices[0].message, 
        timestamp: Date.now(), 
        isImage: false 
    };
    res.json({ success: true, reply });

    chat.messages.push(reply);
    await chat.save();
    await User.updateOne({ _id: userId }, { $inc: { credits: -1 } });

    } catch (error) {
        res.json({ success: false, message: error.message });
    }
};


// Image Generation Message Controller
export const imageMessageController = async (req, res) => {
    try {
        const userId = req.user._id;

        // check user credits
        if(req.user.credits < 2) {
            return res.json({ success: false, message: "You don't have enough credits to use this feature" });
        }

        const { prompt, chatId, isPublished } = req.body;
        // Find chat
        const chat = await Chat.findOne({ userId, _id: chatId });

        // Push user message to chat
        chat.messages.push({ role: "user", content: prompt, timestamp: Date.now(), isImage: false });

        // Encode the prompt to be URL safe
        const encodedPrompt = encodeURIComponent(prompt);

        // Construct ImageKit AI Generation URL
        const generatedImageUrl = `${process.env.IMAGEKIT_URL_ENDPOINT}/ik-genimg-prompt-${encodedPrompt}/QuickGPT/${Date.now()}.png?tr=w-800,h-800`;
        // Trigger image generation by fetching from ImageKit AI URL
        const aiImageResponse = await axios.get(generatedImageUrl, { responseType: "arraybuffer" }); // arraybuffer - Ensures the image is fetched as raw binary data (not JSON or text).

        // convert to Base64
        const base64Image = `data:image/png;base64,${Buffer.from(aiImageResponse.data,"binary").toString("base64")}`;

        // Upload to ImageKit Media Library
        const uploadResponse = await imagekit.upload({
            file: base64Image,
            fileName: `${Date.now()}.png`,
            folder: "QuickGPT"
        });

        const reply = {
            role: "assistant", 
            content: uploadResponse.url, // Use the URL from ImageKit upload response 
            timestamp: Date.now(), 
            isImage: true,
            isPublished
        };
        res.json({ success: true, reply });

        chat.messages.push(reply);
        await chat.save();
        await User.updateOne({ _id: userId }, { $inc: { credits: -2 } });

    } catch (error) {
        res.json({ success: false, message: error.message });
    }
};



