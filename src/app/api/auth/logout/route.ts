import { NextResponse } from "next/server";
import { authCookieName } from "@/lib/auth";

export async function POST() {
  const response = NextResponse.json({ success: true });

  response.cookies.set(authCookieName, "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 0,
    path: "/",
  });

  return response;
}
