"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { getSupabaseBrowserClient } from "@/lib/supabase/browser-client";
import AuthButton from "@/components/AuthButton";
import PasswordInput from "@/components/PasswordInput";
import PhoneInput from 'react-phone-input-2';
import 'react-phone-input-2/lib/style.css';
import { FaCheck, FaXmark } from "react-icons/fa6";
import { toast } from "sonner";
import { initializeVaultKey } from "@/lib/vaultKeyManager";

export default function BioForm() {
  const router = useRouter();
  const supabase = getSupabaseBrowserClient();

  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);

  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    phoneNumber: "",
    password: "",
    verifyPassword: "",
  });

  // --- REAL-TIME VALIDATION STATE ---
  const [validations, setValidations] = useState({
    minLength: false,
    hasLower: false,
    hasUpper: false,
    hasNumber: false,
  });

  useEffect(() => {
    // Check if email exists in session
    const storedEmail = sessionStorage.getItem("registerEmail");
    if (storedEmail) {
      setEmail(storedEmail);
    } else {
      router.push("/register");
    }
  }, [router]);

  // Update validations whenever password changes
  useEffect(() => {
    const pwd = formData.password;
    setValidations({
      minLength: pwd.length >= 8,
      hasLower: /[a-z]/.test(pwd),
      hasUpper: /[A-Z]/.test(pwd),
      hasNumber: /\d/.test(pwd),
    });
  }, [formData.password]);

  const isPasswordValid = Object.values(validations).every(Boolean);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handlePhoneChange = (value: string | undefined) => {
    setFormData({ ...formData, phoneNumber: value || "" });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    // 1. Basic Empty Check
    if (!formData.firstName || !formData.lastName || !formData.phoneNumber || !formData.password || !formData.verifyPassword) {
      toast.warning("Please fill in all fields.");
      setLoading(false);
      return;
    }

    // 2. Password Requirement Check
    if (!isPasswordValid) {
      toast.warning("Password must meet all requirements.");
      setLoading(false);
      return;
    }

    // 3. Match Check
    if (formData.password !== formData.verifyPassword) {
      toast.error("Passwords do not match.");
      setLoading(false);
      return;
    }

    try {
      const { data: signUpData, error: supabaseError } = await supabase.auth.signUp({
        email: email,
        password: formData.password,
        options: {
          data: {
            first_name: formData.firstName,
            last_name: formData.lastName,
            full_name: `${formData.firstName} ${formData.lastName}`.trim(),
            phone: formData.phoneNumber,
          },
        },
      });

      if (supabaseError) throw supabaseError;

      // --- ZERO-KNOWLEDGE KEY SETUP ---
      // Generate salt → Derive Master Key → Generate Vault Key → Wrap → Save
      const userId = signUpData.user?.id;
      if (userId) {
        await initializeVaultKey(formData.password, userId);
      }

      toast.info("Verification code sent to your email.");
      sessionStorage.removeItem("registerEmail");
      router.push(`/register/email-otp?email=${encodeURIComponent(email)}`);

    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "An unexpected error occurred.";
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  // Standard input class to match other forms
  const inputClass = "w-full px-4 py-3.5 rounded-xl border border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-900/50 text-gray-900 dark:text-gray-100 placeholder-gray-400 focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10 focus:bg-white dark:focus:bg-gray-950 transition-all outline-none";
  const labelClass = "block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2 pl-1";

  if (!email) return null;

  return (
    <>
      <form className="pb-10">
        {/* EMAIL (Read-Only) */}
        <div className="pb-5">
          <label className={labelClass}>Email Address</label>
          <input
            type="email"
            value={email}
            disabled
            className={`${inputClass} opacity-60 cursor-not-allowed`}
          />
        </div>

        {/* NAMES - Stacked for full width consistency */}
        <div className="pb-5">
          <label className={labelClass}>First Name</label>
          <input
            name="firstName"
            type="text"
            value={formData.firstName}
            onChange={handleChange}
            placeholder="First Name"
            className={inputClass}
          />
        </div>
        <div className="pb-5">
          <label className={labelClass}>Last Name</label>
          <input
            name="lastName"
            type="text"
            value={formData.lastName}
            onChange={handleChange}
            placeholder="Last Name"
            className={inputClass}
          />
        </div>

        {/* PHONE */}
        <div className="pb-5">
          <label className={labelClass}>Phone Number</label>
          <PhoneInput
            country={'ng'}
            value={formData.phoneNumber}
            onChange={handlePhoneChange}
            containerClass="!w-full"
            inputClass="!w-full !h-[54px] !rounded-xl !border !border-gray-200 dark:!border-gray-800 !bg-gray-50 dark:!bg-gray-900/50 !text-gray-900 dark:!text-gray-100 !pl-[48px] !text-base focus:!border-blue-500 focus:!ring-4 focus:!ring-blue-500/10 !transition-all outline-none"
            buttonClass="!bg-transparent !border-0 !border-r !border-gray-200 dark:!border-gray-800 !rounded-l-xl"
            dropdownClass="!bg-white dark:!bg-gray-950 !border-gray-200 dark:!border-gray-800 !rounded-xl !shadow-xl !text-gray-900 dark:!text-gray-100"
          />
        </div>

        {/* PASSWORD FIELD */}
        <div className="pb-5">
          <label className={labelClass}>Password</label>
          <PasswordInput
            name="password"
            type="password"
            value={formData.password}
            onChange={handleChange}
            placeholder="Password"
            className={inputClass}
          />

          {/* VISUAL CHECKLIST */}
          <div className="grid grid-cols-2 gap-2 mt-4 bg-gray-50 dark:bg-gray-900/30 p-3 rounded-xl border border-gray-100 dark:border-gray-800">
            <PasswordRequirement label="8+ Characters" met={validations.minLength} />
            <PasswordRequirement label="Lowercase Letter" met={validations.hasLower} />
            <PasswordRequirement label="Uppercase Letter" met={validations.hasUpper} />
            <PasswordRequirement label="Number" met={validations.hasNumber} />
          </div>
        </div>

        {/* VERIFY PASSWORD */}
        <div className="pb-8">
          <label className={labelClass}>Verify Password</label>
          <PasswordInput
            name="verifyPassword"
            type="password"
            value={formData.verifyPassword}
            onChange={handleChange}
            placeholder="Verify Password"
            className={`${inputClass} ${formData.verifyPassword && formData.password !== formData.verifyPassword
                ? "!border-red-500 !focus:border-red-500 !bg-red-50 dark:!bg-red-900/10"
                : ""
              }`}
          />
        </div>

        <AuthButton
          variant={isPasswordValid ? "primary" : "disabled"}
          onClick={handleSubmit}
          type="submit"
          loading={loading}
          disabled={loading}
          className="w-full flex justify-center py-4 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white font-bold rounded-xl shadow-lg shadow-blue-500/25 hover:shadow-blue-500/40 hover:-translate-y-0.5 transition-all text-base tracking-wide disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Create Account
        </AuthButton>
      </form>
    </>
  );
}

// --- REUSABLE CHECKLIST ITEM COMPONENT ---
function PasswordRequirement({ label, met }: { label: string; met: boolean }) {
  return (
    <div className={`flex items-center gap-2 text-xs font-medium transition-colors duration-300 ${met ? "text-emerald-700 dark:text-emerald-400" : "text-gray-400"}`}>
      <span className={`flex items-center justify-center w-4 h-4 rounded-full transition-colors duration-300 ${met ? "bg-emerald-100 dark:bg-emerald-900/30" : "bg-gray-200 dark:bg-gray-800"}`}>
        {met ? <FaCheck className="text-[8px] text-emerald-600 dark:text-emerald-400" /> : <FaXmark className="text-[8px] text-gray-400" />}
      </span>
      {label}
    </div>
  );
}