/* =====================================================
   FILE : openai.js
   FUNGSI :
   - Streaming OpenAI
===================================================== */

import OpenAI from "openai";

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

export async function streamChat(res, messages) {
  const stream = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages,
    stream: true
  });

  for await (const chunk of stream) {
    const token = chunk.choices[0]?.delta?.content;
    if (token) res.write(token);
  }
}