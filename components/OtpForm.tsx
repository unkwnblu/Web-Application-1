"use client"; // This MUST be at the top

import { useState, useRef } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { getSupabaseBrowserClient } from "@/lib/supabase/browser-client";
import { createAutoNotification } from "@/app/actions/notifications";
import AuthButton from "@/components/AuthButton";
import Link from "next/link";
import { FaAngleLeft } from "react-icons/fa6";
import { toast } from "sonner";

export default function OtpForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const supabase = getSupabaseBrowserClient();

  const email = searchParams.get("email");

  const [otp, setOtp] = useState<string[]>(new Array(6).fill(""));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  const handleChange = (index: number, value: string) => {
    if (isNaN(Number(value))) return;
    const newOtp = [...otp];
    newOtp[index] = value.substring(value.length - 1);
    setOtp(newOtp);
    if (value && index < 5 && inputRefs.current[index + 1]) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (
    index: number,
    e: React.KeyboardEvent<HTMLInputElement>,
  ) => {
    if (
      e.key === "Backspace" &&
      !otp[index] &&
      index > 0 &&
      inputRefs.current[index - 1]
    ) {
      inputRefs.current[index - 1]?.focus();
    }
  };

  const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData("text").slice(0, 6).split("");
    if (pastedData.every((char) => !isNaN(Number(char)))) {
      const newOtp = [...otp];
      pastedData.forEach((char, index) => {
        if (index < 6) newOtp[index] = char;
      });
      setOtp(newOtp);
      const lastIndex = Math.min(pastedData.length, 5);
      inputRefs.current[lastIndex]?.focus();
    }
  };

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    const token = otp.join("");

    if (token.length !== 6) {
      setError("Please enter the full 6-digit code.");
      setLoading(false);
      return;
    }

    if (!email) {
      setError("Email address is missing. Please go back and try again.");
      setLoading(false);
      return;
    }

    const { error } = await supabase.auth.verifyOtp({
      email,
      token,
      type: "signup",
    });

    if (error) {
      setError(error.message);
      setLoading(false);
    } else {
      toast.success("Account created successfully!");
      createAutoNotification({
        title: "Welcome to Nokslock! \ud83c\udf89",
        message:
          "Your vault has been created successfully. You're now set up to securely store, organize, and protect your most important digital assets.\n\nHere are a few things to get started:\n\u2022 Visit the Vault to begin adding your first entries\n\u2022 Head to Settings to complete your profile and add a Next of Kin\n\u2022 Enable extra security measures to keep your data safe\n\nIf you have any questions, our support team is always here to help. Welcome aboard!",
        type: "success",
      });
      router.push("/dashboard");
      router.refresh();
    }
  };

  const isComplete = otp.every((digit) => digit !== "");

  return (
    <>
      <div className="pb-3">
        <Link href="/register/bio-data/">
          <div className="px-5 flex items-center gap-2 text-blue-400 text-lg font-medium cursor-pointer hover:underline">
            <FaAngleLeft /> Back
          </div>
        </Link>
      </div>

      <h2 className="lg:text-5xl md:text-4xl font-bold mb-8 text-center text-gray-800">
        Enter Verification Code
      </h2>

      <p className="text-center text-lg pb-5 text-gray-600">
        We've sent a verification code to{" "}
        <span className="font-bold text-gray-900">{email || "your email"}</span>
      </p>

      {error && (
        <div className="mx-auto max-w-md mb-6 p-3 rounded-md bg-red-50 border border-red-200 text-red-600 text-sm text-center">
          {error}
        </div>
      )}

      <div className="px-5 md:px-20">
        <form onSubmit={handleVerify}>
          <div className="flex pb-10 pt-5 justify-center gap-3 md:gap-4">
            {otp.map((digit, index) => (
              <div key={index} className="w-12 h-12 md:w-14 md:h-14 relative">
                <input
                  ref={(el) => {
                    inputRefs.current[index] = el;
                  }}
                  type="text"
                  maxLength={1}
                  value={digit}
                  onChange={(e) => handleChange(index, e.target.value)}
                  onKeyDown={(e) => handleKeyDown(index, e)}
                  onPaste={handlePaste}
                  className={`
                    w-full h-full text-center text-2xl font-semibold rounded-lg border outline-none transition-all
                    ${
                      digit
                        ? "border-blue-500 bg-blue-50 text-blue-600"
                        : "border-gray-300 bg-white text-gray-800 focus:border-blue-400 focus:ring-2 focus:ring-blue-100"
                    }
                  `}
                />
              </div>
            ))}
          </div>

          <AuthButton
            variant={isComplete ? "primary" : "disabled"}
            type="submit"
            loading={loading}
            disabled={!isComplete || loading}
          >
            Verify OTP
          </AuthButton>
        </form>

        <p className="text-center mt-6 text-gray-500">
          Didn't receive the code?{" "}
          <button
            type="button"
            className="text-blue-500 font-semibold hover:underline"
          >
            Resend
          </button>
        </p>
      </div>
    </>
  );
}
